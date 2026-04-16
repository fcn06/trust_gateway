use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::collections::HashMap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use x25519_dalek::{StaticSecret, PublicKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce
};
use hkdf::Hkdf;
use sha2::Sha256;
use base64::Engine;

pub mod tenant_router;
pub mod rate_limiter;
pub mod webhooks;
pub mod outbound;
pub mod blind_mailbox;
pub mod ws_relay;

#[derive(Clone)]
struct AppState {
    nats: async_nats::Client,
    private_key: StaticSecret,
}

/// Extended app state for multi-tenant gateway features.
#[derive(Clone)]
pub struct GatewayAppState {
    pub nats: async_nats::Client,
    pub tenant_router: tenant_router::TenantNatsRouter,
    pub rate_limiter: rate_limiter::RateLimiter,
    pub gateway_seed: Vec<u8>,
    /// Phone number → tenant_id mapping for webhook routing.
    pub phone_to_tenant: HashMap<String, String>,
    /// JetStream context for blind mailbox operations.
    pub jetstream: Option<async_nats::jetstream::Context>,
    /// Active wallet WebSocket sessions.
    pub wallet_sessions: ws_relay::WalletSessions,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // -- Check for initialization helper flags --
    let args: Vec<String> = std::env::args().collect();
    let print_pub_only = args.contains(&"--print-pub-key-only".to_string());

    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    tracing::info!("🌐 Public Gateway connecting to NATS at {}", nats_url);
    
    let nats = async_nats::connect(&nats_url).await?;
    tracing::info!("✅ Connected to NATS");

    // Load or Generate Gateway Private Key
    let key_var = std::env::var("GATEWAY_PRIVATE_KEY").unwrap_or_default();
    let private_key = if !key_var.is_empty() {
        let bytes = base64::engine::general_purpose::STANDARD.decode(key_var)
            .expect("Invalid GATEWAY_PRIVATE_KEY base64");
        let arr: [u8; 32] = bytes.try_into().expect("Invalid key length");
        StaticSecret::from(arr)
    } else {
        tracing::warn!("⚠️ GATEWAY_PRIVATE_KEY not set! Generating ephemeral key for testing.");
        StaticSecret::random_from_rng(rand::thread_rng())
    };
    
    let public_key = PublicKey::from(&private_key);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
    
    if print_pub_only {
        println!("{}", pub_b64);
        return Ok(());
    }

    tracing::info!("🔑 PUBLIC KEY (Base64): {}", pub_b64);
    
    let state = AppState { nats: nats.clone(), private_key: private_key.clone() };
    
    // -- Self-Publish DID Document to DHT --
    let gateway_did = std::env::var("GATEWAY_DID").unwrap_or_else(|_| "did:twin:gateway_local".to_string());
    if let Err(e) = publish_gateway_did(&nats, &gateway_did, &pub_b64).await {
        tracing::error!("⚠️ Failed to publish Gateway DID: {}", e);
    }

    // Initialize JetStream for blind mailbox
    let js = async_nats::jetstream::new(nats.clone());
    if let Err(e) = blind_mailbox::init_stream(&js).await {
        tracing::error!("⚠️ Blind Mailbox init failed: {} — continuing without offline storage", e);
    }

    // Multi-tenant gateway state
    let gw_state = GatewayAppState {
        nats: nats.clone(),
        tenant_router: tenant_router::TenantNatsRouter::new(),
        rate_limiter: rate_limiter::RateLimiter::new(rate_limiter::RateLimitConfig::default()),
        gateway_seed: state.private_key.as_bytes().to_vec(),
        phone_to_tenant: HashMap::new(), // TODO: Load from config/env
        jetstream: Some(js),
        wallet_sessions: ws_relay::new_sessions(),
    };

    let webhook_routes = Router::new()
        .route("/twilio", post(webhooks::twilio::twilio_webhook))
        .route("/whatsapp", post(webhooks::whatsapp::whatsapp_webhook))
        .with_state(gw_state.clone());

    // Wallet WebSocket route shares GatewayAppState
    let wallet_routes = Router::new()
        .route("/wallet", axum::routing::any(ws_relay::wallet_ws_handler))
        .with_state(gw_state.clone());

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/register", post(register_handler))
        .route("/ingress", post(didcomm_handler))
        .route("/publish", post(publish_did_handler))
        .route("/did/{did}", get(resolve_did_handler))
        // OID4VP proxy endpoints (dumb HTTP→NATS pipes)
        .route("/oid4vp/request/{node_id}/{request_id}", get(oid4vp_get_request))
        .route("/oid4vp/response/{node_id}/{request_id}", post(oid4vp_submit_response))
        .nest("/webhooks", webhook_routes)
        .nest("/ws", wallet_routes)
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state);

    // Spawn NATS listener for wallet push messages from the Host
    {
        let sessions = gw_state.wallet_sessions.clone();
        let nats_push = nats.clone();
        tokio::spawn(async move {
            match nats_push.subscribe("gateway.push.wallet".to_string()).await {
                Ok(mut sub) => {
                    tracing::info!("📡 Gateway listening on gateway.push.wallet for ActionRequest pushes");
                    while let Some(msg) = futures::StreamExt::next(&mut sub).await {
                        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            let recipient = value.get("recipient_did").and_then(|v| v.as_str()).unwrap_or("");
                            let envelope = value.get("envelope").and_then(|v| v.as_str()).unwrap_or("");
                            if !recipient.is_empty() && !envelope.is_empty() {
                                let pushed = ws_relay::try_push_to_wallet(&sessions, recipient, envelope).await;
                                if !pushed {
                                    tracing::warn!("⚠️ Wallet {} not connected, cannot push ActionRequest", &recipient[..recipient.len().min(30)]);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("❌ Failed to subscribe to gateway.push.wallet: {}", e);
                }
            }
        });
    }

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3002);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("🚀 Public Gateway listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

/// Self-publish Gateway DID Document to DHT at startup.
///
/// SECURITY: This is an internal write (not via the HTTP `POST /publish` endpoint),
/// so no JWS signature verification is needed. The Gateway is the sole authority
/// for its own DID Document. The public `POST /publish` endpoint enforces
/// Ed25519 signature verification for all external submissions.
async fn publish_gateway_did(nats: &async_nats::Client, did: &str, pub_b64: &str) -> anyhow::Result<()> {
    let js = async_nats::jetstream::new(nats.clone());
    let kv = js.get_key_value("dht_discovery").await?;
    
    let did_doc = serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#routing-key", did),
            "type": "X25519KeyAgreementKey2019",
            "controller": did,
            "publicKeyBase64": pub_b64
        }],
        "service": [{
            "id": format!("{}#ingress", did),
            "type": "SAM_Gateway",
            "serviceEndpoint": std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://localhost:3002/ingress".to_string())
        }]
    });

    let blind_id = generate_blind_pointer(did);
    let entry = serde_json::json!({
        "document": did_doc,
        "published_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
    });

    kv.put(blind_id, serde_json::to_vec(&entry)?.into()).await?;
    tracing::info!("📢 Published Gateway DID Document to DHT: {}", did);
    Ok(())
}

pub(crate) fn generate_blind_pointer(did: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(serde::Deserialize)]
struct RegisterRequest {
    node_id: String,
    target_id: String,
}

/// Issues an opaque routing secret containing node_id + target_id
#[derive(serde::Serialize)]
struct RegisterResponse {
    target_id: String,
    gateway_did: String,
    gateway_public_key: String,
}

async fn register_handler(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<RegisterRequest>,
) -> Result<axum::Json<RegisterResponse>, (StatusCode, String)> {
    // 0. Use defaults if not provided in env/config (best effort)
    let gateway_did = std::env::var("GATEWAY_DID").unwrap_or_else(|_| "did:twin:gateway_local".to_string());
    
    // Convert public key to Base64 to return to client
    let pub_key = x25519_dalek::PublicKey::from(&state.private_key);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key.as_bytes());

    let payload = format!("{}.didcomm.{}", req.node_id, req.target_id);
    
    // Derive internal symmetric key for opaque wrapping
    let hk = Hkdf::<Sha256>::new(None, state.private_key.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"sovereign:gateway:internal-wrap", &mut key_bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HKDF failed".to_string()))?;
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // SECURITY FIX: Use random nonce instead of static zero nonce
    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, payload.as_bytes())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed".to_string()))?;

    // Pack: [Nonce(24) | Ciphertext(...)]
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let opaque_target = base64::engine::general_purpose::STANDARD.encode(blob);
    
    Ok(axum::Json(RegisterResponse {
        target_id: opaque_target,
        gateway_did,
        gateway_public_key: pub_b64,
    }))
}

/// Receives Encrypted JIT Routing Token and forwards to NATS
/// The URL path param is the "token" (Base64 URL Safe)
async fn didcomm_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Result<StatusCode, (StatusCode, String)> {
    let token = headers.get("X-Routing-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
        
    if token.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Missing X-Routing-Token header".to_string()));
    }
    
    // 1. Decode Token (Outer JIT Wrapper)
    let token_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&token)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid token base64: {}", e)))?;
        
    if token_bytes.len() < (1 + 32 + 24) {
        return Err((StatusCode::BAD_REQUEST, "Token too short".to_string()));
    }
    
    // 2. Parse Packet: [Version(1)|EphemeralPub(32)|Nonce(24)|Ciphertext(...)]
    let version = token_bytes[0];
    if version != 0x01 {
        return Err((StatusCode::BAD_REQUEST, "Unsupported token version".to_string()));
    }
    
    let ephemeral_pub_bytes: [u8; 32] = token_bytes[1..33].try_into().unwrap();
    let nonce_bytes: [u8; 24] = token_bytes[33..57].try_into().unwrap();
    let ciphertext = &token_bytes[57..];
    
    let ephemeral_public = PublicKey::from(ephemeral_pub_bytes);
    
    // 3. Decrypt Outer JIT Wrapper (Asymmetric)
    let shared_secret = state.private_key.diffie_hellman(&ephemeral_public);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"sovereign:jit-routing", &mut key_bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HKDF failed".to_string()))?;
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| (StatusCode::FORBIDDEN, "Decryption failed - Bad Token".to_string()))?;
        
    let opaque_blob_str = String::from_utf8(decrypted)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid UTF8 in outer token".to_string()))?;

    // 4. Decrypt Inner Opaque Secret (Symmetric)
    let opaque_bytes = base64::engine::general_purpose::STANDARD
        .decode(&opaque_blob_str)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid base64 in opaque secret".to_string()))?;

    // SECURITY FIX: Parse nonce from blob [Nonce(24) | Ciphertext(...)]
    if opaque_bytes.len() < 24 {
        return Err((StatusCode::BAD_REQUEST, "Opaque secret too short".to_string()));
    }
    
    let nonce_internal_bytes: [u8; 24] = opaque_bytes[0..24].try_into().unwrap();
    let ciphertext_internal = &opaque_bytes[24..];

    let hk_internal = Hkdf::<Sha256>::new(None, state.private_key.as_bytes());
    let mut key_bytes_internal = [0u8; 32];
    hk_internal.expand(b"sovereign:gateway:internal-wrap", &mut key_bytes_internal)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HKDF failed".to_string()))?;
    let key_internal = chacha20poly1305::Key::from_slice(&key_bytes_internal);
    let cipher_internal = XChaCha20Poly1305::new(key_internal);

    let nonce_internal = XNonce::from_slice(&nonce_internal_bytes);
    let decrypted_routing = cipher_internal.decrypt(nonce_internal, ciphertext_internal)
        .map_err(|_| (StatusCode::FORBIDDEN, "Invalid Opaque Secret - Decryption failed".to_string()))?;

    let routing_target = String::from_utf8(decrypted_routing)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid UTF8 in internal routing target".to_string()))?;
        
    let nats_subject = format!("v1.{}", routing_target); 
    
    tracing::info!("📨 Decrypted JIT Token. Forwarding to: {}", nats_subject);
    
    state.nats
        .publish(nats_subject.clone(), body.into())
        .await
        .map_err(|e| {
            tracing::error!("❌ NATS publish failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("NATS publish failed: {}", e))
        })?;
    
    Ok(StatusCode::ACCEPTED)
}

/// Resolve a DID Document from the DHT discovery KV store.
/// This is an unprotected endpoint — anyone can look up a published DID.
async fn resolve_did_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let js = async_nats::jetstream::new(state.nats.clone());
    let kv = js.get_key_value("dht_discovery").await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to access DHT store: {}", e),
        ))?;

    let blind_id = generate_blind_pointer(&did);

    let entry = kv.get(&blind_id).await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DHT lookup failed: {}", e),
        ))?
        .ok_or_else(|| (
            StatusCode::NOT_FOUND,
            format!("DID not found: {}", did),
        ))?;

    let stored: serde_json::Value = serde_json::from_slice(&entry)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Corrupt DHT entry: {}", e),
        ))?;

    // Return the nested "document" field if present, otherwise the full entry
    let doc = stored.get("document").cloned().unwrap_or(stored);

    Ok(Json(doc))
}

/// Publishes a DID Document to the DHT discovery KV store.
///
/// SECURITY: Edge-Validation against DHT Poisoning.
/// The caller must submit a JWS-signed envelope (created via `ssi_crypto::signing::pack_signed`).
/// The Gateway verifies:
///   1. The Ed25519 signature is valid (key extracted from the `kid` field).
///   2. The signing DID (from `kid`) matches the `id` field in the DID Document.
/// This prevents an attacker from overwriting a victim's routing info.
async fn publish_did_handler(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Extract the signed envelope string
    let signed_doc_str = body.get("signed_document")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST,
            "Missing 'signed_document' field. DID Documents must be submitted as a signed JWS envelope.".to_string()))?;

    // 2. Verify signature and extract the plaintext DID Document
    let did_doc_str = ssi_crypto::signing::verify_signed(signed_doc_str)
        .map_err(|e| {
            tracing::warn!("🚫 DHT Publish REJECTED — signature verification failed: {}", e);
            (StatusCode::FORBIDDEN, format!("Signature verification failed: {}", e))
        })?;

    // 3. Parse the verified DID Document
    let did_doc: serde_json::Value = serde_json::from_str(&did_doc_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON in signed payload: {}", e)))?;

    let did = did_doc.get("id")
        .and_then(|id| id.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'id' field in DID Document".to_string()))?;

    // 4. Verify that the signing key (kid) matches the document's DID (prevents signing someone else's document)
    let envelope: serde_json::Value = serde_json::from_str(signed_doc_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JWS envelope JSON: {}", e)))?;
    let kid = envelope.get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let kid_did = kid.split('#').next().unwrap_or("");
    if kid_did != did {
        tracing::warn!("🚫 DHT Publish REJECTED — kid DID ({}) ≠ document.id ({})", kid_did, did);
        return Err((StatusCode::FORBIDDEN,
            format!("Signing DID '{}' does not match document id '{}'", kid_did, did)));
    }

    // 5. Signature valid + DID matches → write to DHT
    let js = async_nats::jetstream::new(state.nats.clone());
    let kv = js.get_key_value("dht_discovery").await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to access DHT store: {}", e)))?;

    let blind_id = generate_blind_pointer(did);

    let entry = serde_json::json!({
        "document": did_doc,
        "published_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
    });

    kv.put(blind_id, serde_json::to_vec(&entry).unwrap().into()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to publish to DHT: {}", e)))?;

    tracing::info!("✅ DHT Publish VERIFIED for DID: {}", did);

    Ok(Json(serde_json::json!({ "status": "success", "did": did })))
}

// ─────────────────────────────────────────────────────
// OID4VP Proxy Endpoints (Dumb HTTP→NATS Pipes)
// ─────────────────────────────────────────────────────

/// Proxy a wallet's `request_uri` fetch to the Host via NATS.
///
/// The wallet calls `GET /oid4vp/request/{node_id}/{request_id}` to retrieve
/// the signed OpenID4VP authorization-request JWT. The Gateway forwards
/// the request_id to the Host on `v1.{node_id}.oid4vp.get_request` and
/// returns the Host's JWT response with the standard content type.
async fn oid4vp_get_request(
    State(state): State<AppState>,
    Path((node_id, request_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let subject = format!("v1.{}.oid4vp.get_request", node_id);
    tracing::info!("📡 OID4VP GET proxy: {} → {}", request_id, subject);

    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.nats.request(subject, request_id.into()),
    )
    .await
    .map_err(|_| (StatusCode::GATEWAY_TIMEOUT, "Host did not respond in time".to_string()))?
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("NATS request failed: {}", e)))?;

    let jwt_bytes = reply.payload.to_vec();

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/oauth-authz-req+jwt")],
        jwt_bytes,
    ))
}

/// Proxy the wallet's `direct_post` response submission to the Host via NATS.
///
/// The wallet calls `POST /oid4vp/response/{node_id}/{request_id}` with the
/// VP token and optional ID token. The Gateway wraps the payload with the
/// request_id and forwards to `v1.{node_id}.oid4vp.submit_response`.
async fn oid4vp_submit_response(
    State(state): State<AppState>,
    Path((node_id, request_id)): Path<(String, String)>,
    body: String,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let subject = format!("v1.{}.oid4vp.submit_response", node_id);
    tracing::info!("📡 OID4VP POST proxy: {} → {}", request_id, subject);

    // Wrap the wallet's direct_post body with the request_id for the Host
    let envelope = serde_json::json!({
        "request_id": request_id,
        "body": body,
    });
    let payload = serde_json::to_vec(&envelope)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {}", e)))?;

    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.nats.request(subject, payload.into()),
    )
    .await
    .map_err(|_| (StatusCode::GATEWAY_TIMEOUT, "Host did not respond in time".to_string()))?
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("NATS request failed: {}", e)))?;

    let response: serde_json::Value = serde_json::from_slice(&reply.payload)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Invalid Host response: {}", e)))?;

    Ok(Json(response))
}
