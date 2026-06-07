use std::collections::HashMap;
use std::sync::Arc;
use axum::{
    extract::{State, Json, Path as AxumPath, Query},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
};
use tokio::sync::oneshot;
use anyhow::Result;
use futures::StreamExt;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct AuditExportParams {
    pub limit: Option<usize>,
}
use crate::shared_state::WebauthnSharedState;
use crate::commands::{VaultCommand, AclCommand};
pub use crate::dto::*;
use crate::auth::{extract_claims, resolve_active_did_for_user};
use crate::logic::{compute_local_subject, generate_blind_pointer, publish_to_dht, resolve_did_document_from_dht};
use crate::sovereign::gateway::common_types::MlsMessage;
use sha2::Sha256;
use hmac::{Hmac, Mac};



// --- Logic Functions ---

/// Handles protocol-specific side effects for messages arriving via NATS (O(1) subscription).
/// 
/// ### SECURITY AUDIT (SEC-5)
/// This path is used for `invitation_accepted` and `contact/1.0/request` messages
/// that require immediate Host-side side effects (like updating ACLs or KV stores)
/// before the message is passed to the standard WASM messaging component.
///
/// **What is skipped:**
/// - **Cryptographic Signature Verification:** Currently, this function trusts the
///   underlying NATS transport. It assumes that messages arriving on the node-wildcard
///   subject (`v1.{node_id}.didcomm.>`) are legitimate.
/// - **WASM Handler Dispatch:** These specific protocol types are intercepted here
///   to avoid redundant processing in WASM when a Host-native side effect is required.
///
/// **Trust Model:**
/// In production, NATS is protected by nkeys. Only the Trust Gateway (or components
/// with appropriate nkeys) can publish to these subjects. The Trust Gateway is
/// responsible for verifying the JIT routing token before publishing.
///
/// **FUTURE HARDENING:**
/// This path should be updated to verify Ed25519 signatures of the DIDComm envelope
/// if present, ensuring that even a compromised Gateway cannot spoof protocol side effects.
pub async fn handle_protocol_message_side_effects(
    _state: &WebauthnSharedState,
    _owner_did: &String,
    _msg: &MlsMessage,
    _envelope: &Option<String>,
) -> bool {
    false
}


pub async fn process_send_message_logic(
    shared: Arc<WebauthnSharedState>,
    user_id: String,
    from_did: Option<String>,
    recipient: String,
    message: String,
    typ: String,
    thid: Option<String>,
) -> Result<serde_json::Value, String> {
    if let Some(ext) = shared.messaging_extension.clone() {
        return ext.send_message(shared, user_id, from_did, recipient, message, typ, thid).await;
    }
    tracing::info!("✉️ [Community Edition] process_send_message_logic called (P2P messaging is disabled in Community Edition)");
    Ok(serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() }))
}

pub async fn process_get_messages_logic(
    _shared: Arc<WebauthnSharedState>,
    _user_id: String,
    _filter_did: Option<String>,
) -> Result<Vec<PlainDidcommDto>, String> {
    Ok(Vec::new())
}

pub async fn process_accept_invitation_logic(
    _shared: Arc<WebauthnSharedState>,
    _user_id: String,
    _invitation: OobInvitation,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({ "status": "disabled_in_community_edition" }))
}

// --- Handlers ---

pub async fn send_message_handler(
    State(_shared): State<Arc<WebauthnSharedState>>,
    _headers: HeaderMap,
    Json(_payload): Json<SendMessageRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn get_messages_handler(
    State(_shared): State<Arc<WebauthnSharedState>>, 
    _headers: HeaderMap,
    Query(_query): Query<GetMessagesQuery>,
) -> Result<Json<Vec<PlainDidcommDto>>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn accept_invitation_handler(
    State(_shared): State<Arc<WebauthnSharedState>>,
    _headers: HeaderMap,
    Json(_req): Json<HandshakeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

// ── Identity & Vault handlers ──────────────────────────────

pub async fn create_identity_handler(
    headers: HeaderMap,
    State(shared): State<Arc<WebauthnSharedState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    tracing::info!("📥 received create_identity request");
    let claims = extract_claims(&shared, &headers).await?;
    tracing::info!("👤 create_identity authorized for user {}", claims.user_id);
    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::CreateIdentity(claims.user_id, tx)).await;
    let did = rx.await.unwrap_or_default();
    
    if !did.is_empty() {
        tracing::info!("🆕 Created new DID: {}", did);
        Ok(Json(serde_json::json!({ "status": "ok", "did": did })))
    } else {
        Ok(Json(serde_json::json!({ "status": "error", "message": "Failed to create identity" })))
    }
}

pub async fn export_audit_events_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Query(params): Query<AuditExportParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    
    // Resolve user DIDs to filter activity
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ListIdentities(claims.user_id.clone(), tx)).await;
    let my_dids = rx.await.unwrap_or_default();
    let my_tenant_id = crate::auth::lookup_user_tenant(&shared, &claims.user_id).await
        .unwrap_or_else(|| "default".to_string());

    if let Some(nc) = &shared.nats {
        let js = async_nats::jetstream::new(nc.clone());
        let tenant_prefix = if shared.config.tenant_id.is_empty() {
            String::new()
        } else {
            format!("tenant_{}_", shared.config.tenant_id)
        };
        let stream_name = format!("{}agent_audit_stream", tenant_prefix);
        
        let mut stream = match js.get_stream(&stream_name).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Audit stream not found: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        
        let limit = params.limit.unwrap_or(300);
        
        // FIX: Read the NEWEST events by starting from (total - limit*3).
        // We over-fetch by 3x to account for events filtered out by ownership
        // checks, ensuring we still fill the requested limit with relevant events.
        let stream_info = stream.info().await.ok();
        let last_seq = stream_info
            .map(|info| info.state.last_sequence)
            .unwrap_or(0);
        
        let fetch_count = (limit * 3) as u64; // Over-fetch to handle filtered events
        let start_seq = if last_seq > fetch_count {
            last_seq - fetch_count + 1
        } else {
            1
        };
        
        let consumer_name = format!("audit_export_{}", uuid::Uuid::new_v4());
        let consumer = match stream.create_consumer(async_nats::jetstream::consumer::pull::Config {
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence: start_seq,
            },
            inactive_threshold: std::time::Duration::from_secs(10),
            name: Some(consumer_name.clone()),
            ..Default::default()
        }).await {
            Ok(c) => c,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        
        // Fetch messages from the stream (tail end)
        let mut messages = match consumer.fetch().max_messages(fetch_count as usize).expires(std::time::Duration::from_millis(500)).messages().await {
            Ok(m) => m,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        

        let mut events = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_millis(50), messages.next()).await {
                Ok(Some(Ok(m))) => {
                    if let Ok(event) = serde_json::from_slice::<serde_json::Value>(&m.payload) {
                        // FILTER: Only show events belonging to the user's DIDs, user_id, or tenant
                        let mut belongs_to_user = false;
                        
                        // 1. Match by user_did (DID ownership)
                        if let Some(did) = event.get("user_did").and_then(|v| v.as_str()) {
                            if my_dids.contains(&did.to_string()) {
                                belongs_to_user = true;
                            }
                        }
                        
                        // 2. Match by user_id (explicit user identity, if present in event)
                        if !belongs_to_user {
                            if let Some(uid) = event.get("user_id").and_then(|v| v.as_str()) {
                                if !uid.is_empty() && uid == &claims.user_id {
                                    belongs_to_user = true;
                                }
                            }
                        }
                        
                        // 3. Match by JTI (session correlation — field is "jti" in events)
                        if !belongs_to_user {
                            if let Some(jti) = event.get("jti").and_then(|v| v.as_str()) {
                                if claims.jti.as_deref() == Some(jti) {
                                    belongs_to_user = true;
                                }
                            }
                        }
                        
                        // 4. Match by tenant_id (community/single-tenant fallback)
                        // In single-tenant deployments, all events belong to the user.
                        if !belongs_to_user {
                            if let Some(tid) = event.get("tenant_id").and_then(|v| v.as_str()) {
                                if !tid.is_empty() && !my_tenant_id.is_empty() && tid == my_tenant_id {
                                    belongs_to_user = true;
                                }
                            }
                        }

                        if belongs_to_user {
                            tracing::debug!("✅ Audit match: action={}, user_id_match={}, did_match={}, tenant_match={}, jti_match={}", 
                                event.get("action").and_then(|v| v.as_str()).unwrap_or("?"),
                                event.get("user_id").and_then(|v| v.as_str()) == Some(&claims.user_id),
                                event.get("user_did").and_then(|v| v.as_str()).map(|d| my_dids.contains(&d.to_string())).unwrap_or(false),
                                event.get("tenant_id").and_then(|v| v.as_str()) == Some(my_tenant_id.as_str()),
                                event.get("session_jti").and_then(|v| v.as_str()) == claims.jti.as_deref(),
                            );
                            events.push(event);
                        } else {
                            tracing::trace!("⏭️ Audit skip: action={}, tenant_id={:?}, my_tenant={:?}", 
                                event.get("action").and_then(|v| v.as_str()).unwrap_or("?"),
                                event.get("tenant_id").and_then(|v| v.as_str()),
                                my_tenant_id);
                        }
                    }
                    let _ = m.ack().await;
                }
                _ => break,
            }
        }
        
        let _ = stream.delete_consumer(&consumer_name).await;
        
        // Reverse to newest-first and truncate to requested limit
        events.reverse();
        let has_more = events.len() > limit;
        events.truncate(limit);
        
        Ok(Json(serde_json::json!({
            "tenant_id": shared.config.tenant_id.clone(),
            "events": events,
            "total": events.len(),
            "has_more": has_more
        })))
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}


pub async fn list_identities_handler(
    headers: HeaderMap,
    State(shared): State<Arc<WebauthnSharedState>>,
) -> Result<Json<Vec<crate::dto::EnrichedIdentity>>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;

    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id.clone(), tx)).await;

    let mut enriched = match rx.await {
        Ok(dids) => dids.into_iter().map(|did| crate::dto::EnrichedIdentity { 
            did, 
            alias: String::new(),
            is_institutional: false
        }).collect::<Vec<_>>(),
        Err(e) => {
            tracing::error!("ListIdentities failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("user_identity_metadata") {
            for id in enriched.iter_mut() {
                let safe_did = id.did.trim().replace(":", "_");
                let key = format!("{}_{}", user_id, safe_did);
                if let Ok(Some(entry)) = store.get(&key).await {
                    if let Ok(meta) = serde_json::from_slice::<crate::dto::UserIdentityMetadata>(&entry) {
                        id.alias = meta.alias;
                        id.is_institutional = meta.is_institutional;
                    }
                }
            }
        }
    }
    
    Ok(Json(enriched))
}



pub async fn publish_identity_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(_req): Json<PublishIdentityRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;

    let active_did = resolve_active_did_for_user(shared.clone(), &user_id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    
    // 1. Update published_dids list
    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(pub_store) = kv_stores.get("published_dids") {
             let mut current_dids = Vec::new();
             if let Ok(Some(entry)) = pub_store.get(&user_id).await {
                 if let Ok(existing) = serde_json::from_slice::<Vec<String>>(entry.as_ref()) {
                     current_dids = existing;
                 }
             }
             if !current_dids.contains(&active_did) {
                 current_dids.push(active_did.clone());
                 if let Ok(bytes) = serde_json::to_vec(&current_dids) {
                     let _ = pub_store.put(user_id.clone(), bytes.into()).await;
                 }
             }
        }
    }
    
    // 2. Build the DID Document
    let did_doc = build_complete_did_document(shared.clone(), &active_did).await?;
        
    tracing::info!("📢 [DID] Publishing DID Document to Gateway HTTP Endpoint Layer:\n{}", serde_json::to_string_pretty(&did_doc).unwrap_or_default());
    
    // 3. Sign the DID Document with the user's Ed25519 key (Anti-DHT-Poisoning)
    //    Uses VaultCommand::SignMessage to get the raw Ed25519 signature from the Wasm vault,
    //    then constructs a JWS envelope compatible with ssi_crypto::signing::verify_signed().
    let did_doc_canonical = serde_json::to_string(&did_doc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let payload_bytes = did_doc_canonical.as_bytes();
    
    let (tx_sign, rx_sign) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::SignMessage {
        user_id: user_id.to_string(),
        did: active_did.clone(),
        msg: payload_bytes.to_vec(),
        resp: tx_sign,
    }).await;
    
    let signature_bytes = rx_sign.await
        .map_err(|_| {
            tracing::error!("❌ Vault SignMessage channel closed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            tracing::error!("❌ Vault SignMessage failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Construct JWS envelope matching ssi_crypto::signing::verify_signed() format
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let jws_envelope = serde_json::json!({
        "payload": b64.encode(payload_bytes),
        "signature": b64.encode(&signature_bytes),
        "kid": format!("{}#key-1", active_did)
    });
    let signed_document_str = jws_envelope.to_string();
    
    // 4. Publish via the Gateway HTTP Endpoint (signed envelope)
    let base = shared.config.service_gateway_base_url
        .trim_end_matches('/')
        .trim_end_matches("ingress")
        .trim_end_matches('/');
        
    let publish_url = format!("{}/publish", base);
    let publish_payload = serde_json::json!({
        "signed_document": signed_document_str
    });
    
    let client = shared.http_client.clone();
    match client.post(&publish_url).json(&publish_payload).send().await {
        Ok(res) if res.status().is_success() => {
            tracing::info!("✅ Gateway HTTP publish succeeded (signed)");
        },
        Ok(res) => {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            tracing::error!("❌ Gateway HTTP publish failed ({}): {}", status, body);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        },
        Err(e) => {
            tracing::error!("❌ Gateway HTTP publish network error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    
    Ok(Json(serde_json::json!({ "status": "success", "did": active_did })))
}

pub async fn build_complete_did_document(
    shared: Arc<WebauthnSharedState>,
    active_did: &str,
) -> Result<serde_json::Value, StatusCode> {
    // 1. Extract public key from did:twin:z or did:peer:z string
    let mut verification_methods = vec![];
    if let Some(hex_part) = identity_context::did::extract_hex_pubkey(active_did) {
        if let Ok(pub_bytes) = hex::decode(hex_part) {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);
            verification_methods.push(serde_json::json!({
                "id": format!("{}#key-1", active_did),
                "type": "Ed25519VerificationKey2018",
                "controller": active_did,
                "publicKeyBase64": b64
            }));
        }
    }
    
    // Construct base DID Doc
    let mut did_doc = serde_json::json!({
        "id": active_did,
        "verificationMethod": verification_methods,
        "authentication": [],
        "service": []
    });
    
    // Construct Internal Subject (used by both Legacy and JIT)
    let node_id = crate::logic::compute_node_id(&shared.house_salt);
    let subject = compute_local_subject(&active_did, &shared.house_salt);
    
    let endpoint_val = if !shared.config.gateway_did.is_empty() {
        // --- JIT Routing (Resilient Coordination) ---
        if shared.config.service_gateway_base_url.is_empty() {
             tracing::error!("❌ Gateway DID configured ('{}') but Service URL is empty", shared.config.gateway_did);
             return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        // 1. Get Opaque Routing Secret from Gateway
        let client = shared.http_client.clone();
        let base = shared.config.service_gateway_base_url
            .trim_end_matches('/')
            .trim_end_matches("ingress")
            .trim_end_matches('/');
        
        let reg_url = format!("{}/register", base);
        tracing::info!("🔒 Requesting JIT Routing Secret from {}", reg_url);
        
        let reg_res = client.post(&reg_url)
            .json(&serde_json::json!({ "node_id": node_id, "target_id": subject }))
            .send()
            .await;

        match reg_res {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(resp_text) = resp.text().await {
                    // Check if response is JSON (New Format) or Raw String (Old Format)
                    if let Ok(json_resp) = serde_json::from_str::<serde_json::Value>(&resp_text) {
                        if let (Some(tid), Some(gw_did), Some(gw_pub)) = (
                            json_resp["target_id"].as_str(),
                            json_resp["gateway_did"].as_str(),
                            json_resp["gateway_public_key"].as_str()
                        ) {
                            tracing::info!("🔒 JIT Coordination SUCCESS. Gateway DID: {}", gw_did);
                            
                            // --- SELF-HEALING: Republish Gateway DID to DHT ---
                            let gateway_doc = serde_json::json!({
                                "id": gw_did,
                                "verificationMethod": [{
                                    "id": format!("{}#routing-key", gw_did),
                                    "type": "X25519KeyAgreementKey2019",
                                    "controller": gw_did,
                                    "publicKeyBase64": gw_pub
                                }],
                                "service": [{
                                    "id": format!("{}#ingress", gw_did),
                                    "type": "SAM_Gateway",
                                    "serviceEndpoint": shared.config.service_gateway_base_url
                                }]
                            });
                            
                            let dht_store_opt = shared.kv_stores.as_ref().and_then(|kv| kv.get("dht_discovery"));
                            let _ = publish_to_dht(
                                &shared.http_client,
                                &shared.config.service_gateway_base_url,
                                dht_store_opt,
                                &gateway_doc,
                                None
                            ).await;
                            
                            serde_json::json!({
                                "uri": shared.config.service_gateway_base_url,
                                "routing_did": shared.config.gateway_did,
                                "target_id": tid
                            })
                        } else {
                            tracing::error!("❌ JIT Response malformed JSON");
                            return Err(StatusCode::BAD_GATEWAY);
                        }
                    } else {
                        tracing::warn!("⚠️ Received raw string from Gateway (Old Version?)");
                        serde_json::json!({
                            "uri": shared.config.service_gateway_base_url,
                            "routing_did": shared.config.gateway_did,
                            "target_id": resp_text
                        })
                    }
                } else {
                    tracing::error!("❌ JIT Coordination failed: Empty response body");
                    return Err(StatusCode::BAD_GATEWAY);
                }
            },
            Ok(resp) => {
                 tracing::warn!("⚠️ JIT Coordination failed ({}). Falling back to legacy.", resp.status());
                if !shared.config.service_gateway_base_url.is_empty() {
                     serde_json::Value::String(format!("{}/messaging/{}", shared.config.service_gateway_base_url, subject))
                } else {
                     serde_json::Value::String(format!("nats://v1.{}.didcomm.{}", node_id, subject))
                }
            },
            Err(e) => {
                tracing::warn!("⚠️ JIT Coordination failed (Network error {}). Falling back to legacy.", e);
                if !shared.config.service_gateway_base_url.is_empty() {
                     serde_json::Value::String(format!("{}/messaging/{}", shared.config.service_gateway_base_url, subject))
                } else {
                     serde_json::Value::String(format!("nats://v1.{}.didcomm.{}", node_id, subject))
                }
            }
        }
    } else {
        // --- Legacy / Direct NATS ---
        tracing::warn!("⚠️ No Gateway DID configured. Falling back to Legacy String Endpoint.");
        if !shared.config.service_gateway_base_url.is_empty() {
             serde_json::Value::String(format!("{}/messaging/{}", shared.config.service_gateway_base_url, subject))
        } else {
             serde_json::Value::String(format!("nats://v1.{}.didcomm.{}", node_id, subject))
        }
    };
    
    let service = serde_json::json!({
        "id": format!("{}#messaging", active_did),
        "type": "MessagingService",
        "serviceEndpoint": endpoint_val
    });
    
    if let Some(services) = did_doc["service"].as_array_mut() {
        services.push(service);
    }
    
    Ok(did_doc)
}



#[derive(Deserialize)]
pub struct EnrichIdentityRequest {
    pub did: String,
    pub alias: String,
    pub is_institutional: Option<bool>,
}

pub async fn enrich_identity_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(req): Json<EnrichIdentityRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;
    
    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("user_identity_metadata") {
            // Enforcement: Only allow setting is_institutional if the tenant is in the allowed list
            if req.is_institutional.unwrap_or(false) {
                // Determine tenant_id from claims or session
                let tenant_id = match claims.tenant_id {
                    Some(tid) => tid,
                    None => {
                        // Fallback to resolving AID if tenant_id is missing from claims
                        let (tx, rx) = oneshot::channel();
                        let _ = shared.vault_cmd_tx.send(VaultCommand::GetHmacSecret { user_id: user_id.clone(), resp: tx }).await;
                        if let Ok(Ok(secret)) = rx.await {
                            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).expect("BUG: HMAC-SHA256 accepts any key length");
                            mac.update(b"login");
                            hex::encode(mac.finalize().into_bytes())
                        } else {
                            return Err(StatusCode::INTERNAL_SERVER_ERROR);
                        }
                    }
                };

                let allowed = &shared.config.allowed_agent_tenants;
                let is_allowed = if allowed.is_empty() {
                    false
                } else {
                    allowed.split(',').any(|s| s.trim() == tenant_id)
                };

                if !is_allowed {
                    tracing::warn!("🚫 Tenant {} attempted to enable institutional agent but is NOT in the allowed list", tenant_id);
                    return Err(StatusCode::FORBIDDEN);
                }
            }

            let safe_did = req.did.trim().replace(":", "_");
            let key = format!("{}_{}", user_id, safe_did);
            let meta = crate::dto::UserIdentityMetadata { 
                alias: req.alias.clone(),
                is_institutional: req.is_institutional.unwrap_or(false),
            };
            tracing::info!("📝 Enriching identity metadata for key: {}, alias: {}", key, req.alias);
            if let Ok(val) = serde_json::to_vec(&meta) {
                 match store.put(key.clone(), val.into()).await {
                     Ok(_) => {
                         tracing::info!("✅ Successfully wrote identity metadata for key: {}", key);
                         return Ok(Json(serde_json::json!({ "status": "success" })));
                     },
                     Err(e) => {
                         tracing::error!("❌ Failed to write identity metadata for key {}: {}", key, e);
                     }
                 }
            } else {
                 tracing::error!("❌ Failed to serialize identity metadata for key: {}", key);
            }
        } else {
             tracing::error!("❌ user_identity_metadata KV store not found in kv_stores");
        }
    } else {
         tracing::error!("❌ kv_stores is None in WebauthnSharedState");
    }
    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn get_contact_requests_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<ContactRequestsResponse>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    
    // Resolve all user DIDs
    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(claims.user_id.clone(), tx)).await;
    let user_dids = rx.await.unwrap_or_default();
    
    // Identify the Active DID (context for determining INCOMING vs OUTGOING)
    let active_did = resolve_active_did_for_user(shared.clone(), &claims.user_id).await.ok();
    
    let mut requests = Vec::new();
    
    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("contact_requests") {
            if let Ok(mut keys) = store.keys().await {
                 while let Some(Ok(key)) = keys.next().await {
                     if let Ok(Some(entry)) = store.get(&key).await {
                         if let Ok(mut req) = serde_json::from_slice::<ContactRequest>(&entry) {
                             // Strict Ownership: You only "see" a contact request record if YOU are the owner of that record in the KV store
                             if !user_dids.contains(&req.owner_did) {
                                 continue;
                             }

                             // If an identity is active, only show requests explicitly owned by that identity
                             if let Some(active) = &active_did {
                                 if &req.owner_did != active {
                                     continue;
                                 }
                             }

                             // The request role (INCOMING or OUTGOING) is already set correctly in KV during creation
                             requests.push(req);
                         }
                     }
                 }
            }
        }
    }
    
    Ok(Json(ContactRequestsResponse { requests }))
}

pub async fn get_acl_policies_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::sovereign::gateway::common_types::ConnectionPolicy>>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    
    // Resolve active DID for this user
    let active_did = resolve_active_did_for_user(shared.clone(), &claims.user_id).await
        .unwrap_or_else(|_| claims.user_id.clone()); // Fallback to UUID if no DID
        
    let (tx, rx) = oneshot::channel();
    let _ = shared.acl_cmd_tx.send(AclCommand::GetPolicies { owner: active_did, resp: tx }).await;
    let mut policies = rx.await.unwrap_or_default();
    
    // Bug Fix: Enrich policies with aliases from user_identity_metadata
    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("user_identity_metadata") {
            for policy in policies.iter_mut() {
                let safe_did = policy.did.trim().replace(":", "_");
                let key = format!("{}_{}", claims.user_id, safe_did);
                if let Ok(Some(entry)) = store.get(&key).await {
                    if let Ok(meta) = serde_json::from_slice::<crate::dto::UserIdentityMetadata>(&entry) {
                        if !meta.alias.is_empty() {
                            policy.alias = meta.alias;
                        }
                    }
                }
            }
        }
    }
    
    Ok(Json(policies))
}

pub async fn update_acl_policy_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    
    // Resolve active DID for this user
    let active_did = resolve_active_did_for_user(shared.clone(), &claims.user_id).await
        .unwrap_or_else(|_| claims.user_id.clone()); // Fallback to UUID if no DID

    let (tx, rx) = oneshot::channel();
    let _ = shared.acl_cmd_tx.send(AclCommand::UpdatePolicy { 
        owner: active_did, 
        policy: req.policy, 
        resp: tx 
    }).await;
    match rx.await {
        Ok(Ok(_)) => Ok(Json(serde_json::json!({ "status": "success" }))),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_published_dids_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let mut published = Vec::new();
    if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("published_dids")) {
         if let Ok(Some(entry)) = kv.get(&claims.user_id).await {
              if let Ok(identities) = serde_json::from_slice::<Vec<String>>(entry.as_ref()) {
                   published = identities;
              }
         }
    }
    Ok(Json(published))
}

pub async fn get_active_did_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;

    // Use the full resolver with auto-unlock and auto-heal fallback,
    // not the raw VaultCommand which can return empty if vault is locked
    match crate::auth::logic::resolve_active_did_for_user(shared.clone(), &claims.user_id).await {
        Ok(did) => Ok(Json(serde_json::Value::String(did))),
        Err(_) => {
            // Fallback to empty string rather than error, so the UI can still render
            tracing::warn!("⚠️ get_active_did_handler: No active DID resolvable for {}", claims.user_id);
            Ok(Json(serde_json::Value::String(String::new())))
        }
    }
}

#[derive(Deserialize)]
pub struct ActivateIdentityRequest {
    pub did: String,
}

pub async fn activate_identity_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(req): Json<ActivateIdentityRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::SetActiveDid(claims.user_id, req.did.trim().to_string(), tx)).await;
    match rx.await {
        Ok(Ok(true)) => Ok(Json(serde_json::json!({ "status": "success" }))),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn accept_contact_request_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    AxumPath(req_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    
    // 1. Retrieve Request
    let kv_stores = shared.kv_stores.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let store = kv_stores.get("contact_requests").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let entry = store.get(&req_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let mut request: ContactRequest = serde_json::from_slice(&entry).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // SECURITY: Ensure the user actually owns the DID that received this request (preventing sender approval)
    let (tx_l, rx_l) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(claims.user_id.clone(), tx_l)).await;
    let my_dids = rx_l.await.unwrap_or_default();
    
    if !my_dids.contains(&request.owner_did) {
        tracing::warn!("🔒 Unauthorized contact acceptance attempt: User {} does not own DID {}", claims.user_id, request.owner_did);
        return Err(StatusCode::FORBIDDEN);
    }

    // FUNCTIONAL SECURITY: Only allow approval if the recipient DID is currently ACTIVE
    let active_did = resolve_active_did_for_user(shared.clone(), &claims.user_id).await.ok();
    if let Some(current) = active_did {
        if request.owner_did != current {
            tracing::warn!("🔒 Action blocked: Cannot approve request for {} while {} is active", request.owner_did, current);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    if request.status == "ACCEPTED" {
        return Ok(Json(serde_json::json!({"status": "already_accepted"})));
    }
    
    // 2. Update ACL
    let policy = crate::sovereign::gateway::common_types::ConnectionPolicy {
        did: request.sender_did.clone(),
        alias: format!("Contact {}", &request.sender_did[..8]),
        created_at: chrono::Utc::now().timestamp(),
        permissions: vec![
            crate::sovereign::gateway::common_types::Permission::Chat, 
            crate::sovereign::gateway::common_types::Permission::Discovery
        ],
        status: crate::sovereign::gateway::common_types::ConnectionStatus::Active,
    };
    
    let (tx, rx) = oneshot::channel();
    let _ = shared.acl_cmd_tx.send(AclCommand::UpdatePolicy { owner: request.owner_did.clone(), policy, resp: tx }).await;
    let _ = rx.await;
    
    // 3. Send Acceptance Message (include DID Document for ledgerless resolution)
    let did_doc_json = build_complete_did_document(shared.clone(), &request.owner_did).await
        .unwrap_or(serde_json::json!({}));
    
    let body = serde_json::json!({
        "status": "accepted",
        "responder_did": request.owner_did,
        "did_document": did_doc_json
    }).to_string();
    
    let _ = process_send_message_logic(shared.clone(), claims.user_id, Some(request.owner_did.clone()), request.sender_did.clone(), body, "https://lianxi.io/protocols/contact/1.0/acceptance-response".to_string(), None).await;
    
    // 4. Update Request Status
    request.status = "ACCEPTED".to_string();
    if let Ok(bytes) = serde_json::to_vec(&request) {
        let _ = store.put(req_id, bytes.into()).await;
    }
    
    Ok(Json(serde_json::json!({"status": "accepted"})))
}

pub async fn refuse_contact_request_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    AxumPath(req_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    
    let kv_stores = shared.kv_stores.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let store = kv_stores.get("contact_requests").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let entry = store.get(&req_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
        
    let mut request: ContactRequest = serde_json::from_slice(&entry).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // SECURITY: Ensure the user actually owns the DID that received this request
    let (tx_l, rx_l) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(claims.user_id.clone(), tx_l)).await;
    let my_dids = rx_l.await.unwrap_or_default();
    if !my_dids.contains(&request.owner_did) {
        tracing::warn!("🔒 Unauthorized contact refusal attempt: User {} does not own DID {}", claims.user_id, request.owner_did);
        return Err(StatusCode::FORBIDDEN);
    }
    
    // FUNCTIONAL SECURITY: Only allow refusal if the recipient DID is currently ACTIVE
    let active_did = resolve_active_did_for_user(shared.clone(), &claims.user_id).await.ok();
    if let Some(current) = active_did {
        if request.owner_did != current {
            tracing::warn!("🔒 Action blocked: Cannot refuse request for {} while {} is active", request.owner_did, current);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    request.status = "REFUSED".to_string();
    if let Ok(bytes) = serde_json::to_vec(&request) {
        let _ = store.put(req_id, bytes.into()).await;
    }
    
    Ok(Json(serde_json::json!({"status": "refused"})))
}

pub async fn generate_invitation_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let active_did = resolve_active_did_for_user(shared.clone(), &claims.user_id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    
    let invitation_id = uuid::Uuid::new_v4().to_string();
    let inv = OobInvitation {
        id: invitation_id,
        r#type: "https://didcomm.org/out-of-band/1.0/invitation".to_string(),
        from: active_did.clone(),
        body: InvitationBody {
            goal_code: "connect".to_string(),
            goal: "Establish connection".to_string(),
            accept: vec!["didcomm/v2".to_string()],
        },
        services: None,
    };
    
    let inv_value = serde_json::to_value(inv).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(inv_value))
}


pub async fn get_profile_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<crate::dto::UserProfile>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("user_profiles") {
            if let Ok(Some(entry)) = store.get(&user_id).await {
                if let Ok(profile) = serde_json::from_slice::<crate::dto::UserProfile>(entry.as_ref()) {
                    return Ok(Json(profile));
                }
            }
        }
    }
    // Fallback: Return basic profile from claims if store fails
    Ok(Json(crate::dto::UserProfile {
        user_id: user_id.clone(),
        username: claims.username,
        country: None,
    }))
}

pub async fn update_profile_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(req): Json<crate::dto::UpdateProfileRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("user_profiles") {
             // 1. Get existing profile
             let mut profile = if let Ok(Some(entry)) = store.get(&user_id).await {
                 serde_json::from_slice::<crate::dto::UserProfile>(entry.as_ref()).unwrap_or(crate::dto::UserProfile {
                     user_id: user_id.clone(),
                     username: claims.username.clone(),
                     country: None,
                 })
             } else {
                 crate::dto::UserProfile {
                     user_id: user_id.clone(),
                     username: claims.username.clone(),
                     country: None,
                 }
             };

             // 2. Update fields
             if let Some(c) = req.country {
                 profile.country = Some(c);
             }

             // 3. Save
             if let Ok(val) = serde_json::to_vec(&profile) {
                 let _ = store.put(user_id, val.into()).await;
                 return Ok(Json(serde_json::json!({ "status": "success", "profile": profile })));
             }
        }
    }
    Err(StatusCode::INTERNAL_SERVER_ERROR)
}
// --- DIDComm over HTTP Handler ---
pub async fn receive_didcomm_http_wrapper(
    State(shared): State<Arc<WebauthnSharedState>>,
    AxumPath(subject): AxumPath<String>,
    body: String, // The body is the raw envelope string
) -> Response {
    tracing::info!("📥 [HTTP] Received DIDComm envelope for subject: {}", subject);

    // Forward to NATS using the O(1) wildcard subject format: v1.{node_id}.didcomm.{subject}
    if let Some(nc) = &shared.nats {
        let node_id = crate::logic::compute_node_id(&shared.house_salt);
        let nats_subject = format!("v1.{}.didcomm.{}", node_id, subject);
        
        match nc.publish(nats_subject.clone(), body.into()).await {
            Ok(_) => {
                tracing::info!("✅ [HTTP->NATS] Forwarded to {}", nats_subject);
                StatusCode::OK.into_response()
            },
            Err(e) => {
                tracing::error!("❌ [HTTP->NATS] Publish failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        tracing::error!("❌ [HTTP] NATS not available to forward message");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

// --- Escalation Request Handlers ---

pub async fn get_escalation_requests_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<EscalationRequestsResponse>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ListIdentities(claims.user_id.clone(), tx)).await;
    let my_dids = rx.await.unwrap_or_default();

    let mut requests = Vec::new();

    let mut raw_requests = Vec::new();

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("escalation_requests") {
            if let Ok(mut keys) = store.keys().await {
                while let Some(Ok(key)) = keys.next().await {
                    if let Ok(Some(entry)) = store.get(&key).await {
                        if let Ok(req) = serde_json::from_slice::<EscalationRequest>(&entry) {
                            raw_requests.push((key, req));
                        }
                    }
                }
            }
        }
    }

    // Now process them outside the KV keys stream to prevent async deadlocks
    for (key, req) in raw_requests {
        let mut belongs_to_user = false;
        
        if let Some(uid) = &req.owner_user_id {
            if uid == &claims.user_id {
                belongs_to_user = true;
            }
        }
        
        // Fallback for transition/legacy records: only allow if requester_did resolves to this user
        if !belongs_to_user {
            let (tx1, rx1) = tokio::sync::oneshot::channel();
            let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid { did: req.requester_did.clone(), resp: tx1 }).await;
            if let Ok(Some(uid)) = rx1.await {
                if uid == claims.user_id {
                    belongs_to_user = true;
                }
            }
        }

        tracing::info!("🔍 Escalation filter: key={}, req.owner={:?}, claims.user_id={}, belongs_to_user={}", key, req.owner_user_id, claims.user_id, belongs_to_user);
        if belongs_to_user {
            requests.push(req);
        }
    }

    // Sort by created_at (newest first)
    requests.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(Json(EscalationRequestsResponse { requests }))
}

pub async fn approve_escalation_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    AxumPath(req_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;

    let kv_stores = shared.kv_stores.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let store = kv_stores.get("escalation_requests").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut entry_opt = None;
    let mut actual_key = String::new();
    
    // First try the expected new key format (approver == owner)
    let expected_key = format!("{}_{}", claims.user_id, req_id);
    if let Ok(Some(e)) = store.get(&expected_key).await {
        entry_opt = Some(e);
        actual_key = expected_key;
    } else if let Ok(Some(e)) = store.get(&req_id).await {
        // Try legacy format
        entry_opt = Some(e);
        actual_key = req_id.clone();
    } else {
        // We might be the requester approving an institutional agent's request.
        // We must scan for a key ending with :req_id
        if let Ok(mut keys) = store.keys().await {
            while let Some(Ok(k)) = keys.next().await {
                if k.ends_with(&format!("_{}", req_id)) {
                    if let Ok(Some(e)) = store.get(&k).await {
                        entry_opt = Some(e);
                        actual_key = k;
                        break;
                    }
                }
            }
        }
    }
    
    let entry = entry_opt.ok_or(StatusCode::NOT_FOUND)?;

    let mut request: EscalationRequest = serde_json::from_slice(&entry)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // SECURITY: Verify the authenticated user owns this escalation request OR is the requester
    let mut authorized = false;
    if let Some(ref owner_uid) = request.owner_user_id {
        if owner_uid == &claims.user_id {
            authorized = true;
        }
    }
    
    if !authorized {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ListIdentities(claims.user_id.clone(), tx)).await;
        let my_dids = rx.await.unwrap_or_default();
        if my_dids.contains(&request.requester_did) || my_dids.contains(&request.user_did) {
            authorized = true;
        } else {
            let (tx1, rx1) = tokio::sync::oneshot::channel();
            let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid { did: request.requester_did.clone(), resp: tx1 }).await;
            if let Ok(Some(uid)) = rx1.await {
                if uid == claims.user_id {
                    authorized = true;
                }
            }
            if !authorized {
                let (tx2, rx2) = tokio::sync::oneshot::channel();
                let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid { did: request.user_did.clone(), resp: tx2 }).await;
                if let Ok(Some(uid)) = rx2.await {
                    if uid == claims.user_id {
                        authorized = true;
                    }
                }
            }
        }
    }

    if !authorized {
        tracing::warn!("🔒 Unauthorized escalation approval: user {} tried to approve request", claims.user_id);
        return Err(StatusCode::FORBIDDEN);
    }

    if request.status != "PENDING" {
        return Ok(Json(serde_json::json!({"status": "already_processed"})));
    }

    // Mint an elevated JWT with short TTL, scoped to the specific tool
    let scope = vec![
        "mcp:execute".to_string(),
        "clearance:elevated".to_string(),
        format!("tool:{}", request.tool_name),
    ];
    let elevated_ttl = 30u32; // 30 seconds — very short to prevent replay

    // Resolve tenant_id for the elevated JWT (proper tenant membership lookup)
    let tenant_id = if shared.config.tenant_id.is_empty() {
        crate::auth::lookup_user_tenant(&shared, &claims.user_id).await
            .unwrap_or_default()
    } else {
        shared.config.tenant_id.clone()
    };

    // Resolve active DID for the approving user in case request DID is empty
    let approving_did = match crate::auth::resolve_active_did_for_user(shared.clone(), &claims.user_id).await {
        Ok(did) => did,
        Err(_) => return Err(StatusCode::FORBIDDEN),
    };

    // WS-A3: Replaced `todo_verify_in_layer_above` sentinel with proper emptiness check.
    // If user_did is absent or empty, fall back to the approving user's active DID.
    let effective_user_did = if request.user_did.is_empty() {
        approving_did
    } else {
        request.user_did.clone()
    };

    let (tx_jwt, rx_jwt) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::IssueSessionJwt {
        user_id: claims.user_id.clone(),
        subject: effective_user_did.clone(),
        scope,
        user_did: effective_user_did,
        ttl_seconds: elevated_ttl,
        tenant_id,
        resp: tx_jwt,
    }).await;

    // WS-A1: JWT minting failure is now a hard error. Publishing an approval
    // with a null/empty JWT would be a silent security degradation — the
    // consumer (mcp_nats_bridge) needs a valid elevated JWT to re-execute
    // the tool with elevated privileges.
    let elevated_jwt = match rx_jwt.await {
        Ok(Ok(token)) => token,
        Ok(Err(e)) => {
            tracing::error!("🚨 Failed to mint elevated JWT for approval — aborting: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Err(e) => {
            tracing::error!("🚨 Vault command channel failed during approval — aborting: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Publish the elevated JWT to the stored NATS reply subject
    if let Some(nats) = &shared.nats {
        let reply_payload = serde_json::json!({
            "status": "APPROVED",
            "elevated_jwt": elevated_jwt,
        });
        if let Err(e) = nats.publish(
            request.nats_reply_subject.clone(),
            serde_json::to_string(&reply_payload).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.into(),
        ).await {
            tracing::error!("❌ Failed to publish escalation approval via NATS: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        tracing::info!("✅ Published escalation approval for tool '{}' to {}", request.tool_name, request.nats_reply_subject);

        // ── Bridge approval to Trust Gateway via NATS ────────
        // The gateway's approval_daemon watches its `approval_records`
        // KV. Publish the decision so the gateway updates its store
        // and triggers execution.
        let decision_payload = serde_json::json!({
            "approval_id": req_id,
            "decision": "approve",
            "resolved_by": claims.user_id,
        });
        if let Err(e) = nats.publish(
            "gateway.v1.approval.decision".to_string(),
            serde_json::to_string(&decision_payload).unwrap_or_default().into(),
        ).await {
            tracing::warn!("⚠️ Failed to publish approval decision to gateway: {}", e);
        } else {
            tracing::info!("📩 Bridged approval to gateway via NATS (approval_id: {})", req_id);
        }
    }

    // Update status
    request.status = "APPROVED".to_string();
    let save_key = if let Some(ref uid) = request.owner_user_id { format!("{}_{}", uid, req_id) } else { req_id.clone() };
    if let Ok(bytes) = serde_json::to_vec(&request) {
        let _ = store.put(save_key, bytes.into()).await;
    }

    Ok(Json(serde_json::json!({"status": "approved"})))
}

pub async fn deny_escalation_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    AxumPath(req_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;

    let kv_stores = shared.kv_stores.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let store = kv_stores.get("escalation_requests").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut entry_opt = None;
    let mut actual_key = String::new();
    
    let expected_key = format!("{}_{}", claims.user_id, req_id);
    if let Ok(Some(e)) = store.get(&expected_key).await {
        entry_opt = Some(e);
        actual_key = expected_key;
    } else if let Ok(Some(e)) = store.get(&req_id).await {
        entry_opt = Some(e);
        actual_key = req_id.clone();
    } else {
        if let Ok(mut keys) = store.keys().await {
            while let Some(Ok(k)) = keys.next().await {
                if k.ends_with(&format!("_{}", req_id)) {
                    if let Ok(Some(e)) = store.get(&k).await {
                        entry_opt = Some(e);
                        actual_key = k;
                        break;
                    }
                }
            }
        }
    }
    
    let entry = entry_opt.ok_or(StatusCode::NOT_FOUND)?;

    let mut request: EscalationRequest = serde_json::from_slice(&entry)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // SECURITY: Verify the authenticated user owns this escalation request OR is the requester
    let mut authorized = false;
    if let Some(ref owner_uid) = request.owner_user_id {
        if owner_uid == &claims.user_id {
            authorized = true;
        }
    }
    
    if !authorized {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ListIdentities(claims.user_id.clone(), tx)).await;
        let my_dids = rx.await.unwrap_or_default();
        if my_dids.contains(&request.requester_did) || my_dids.contains(&request.user_did) {
            authorized = true;
        } else {
            let (tx1, rx1) = tokio::sync::oneshot::channel();
            let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid { did: request.requester_did.clone(), resp: tx1 }).await;
            if let Ok(Some(uid)) = rx1.await {
                if uid == claims.user_id {
                    authorized = true;
                }
            }
            if !authorized {
                let (tx2, rx2) = tokio::sync::oneshot::channel();
                let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid { did: request.user_did.clone(), resp: tx2 }).await;
                if let Ok(Some(uid)) = rx2.await {
                    if uid == claims.user_id {
                        authorized = true;
                    }
                }
            }
        }
    }

    if !authorized {
        tracing::warn!("🔒 Unauthorized escalation denial: user {} tried to deny request", claims.user_id);
        return Err(StatusCode::FORBIDDEN);
    }

    if request.status != "PENDING" {
        return Ok(Json(serde_json::json!({"status": "already_processed"})));
    }

    // Publish denial to the stored NATS reply subject
    if let Some(nats) = &shared.nats {
        let reply_payload = serde_json::json!({
            "status": "DENIED",
            "message": format!("User denied permission for tool: {}", request.tool_name),
        });
        if let Err(e) = nats.publish(
            request.nats_reply_subject.clone(),
            serde_json::to_string(&reply_payload).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.into(),
        ).await {
            tracing::error!("❌ Failed to publish escalation denial via NATS: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        tracing::info!("🚫 Published escalation denial for tool '{}' to {}", request.tool_name, request.nats_reply_subject);

        // ── Bridge denial to Trust Gateway via NATS ──────────
        let decision_payload = serde_json::json!({
            "approval_id": req_id,
            "decision": "deny",
            "resolved_by": claims.user_id,
        });
        if let Err(e) = nats.publish(
            "gateway.v1.approval.decision".to_string(),
            serde_json::to_string(&decision_payload).unwrap_or_default().into(),
        ).await {
            tracing::warn!("⚠️ Failed to publish denial decision to gateway: {}", e);
        } else {
            tracing::info!("📩 Bridged denial to gateway via NATS (approval_id: {})", req_id);
        }
    }

    // Update status
    request.status = "DENIED".to_string();
    let save_key = if let Some(ref uid) = request.owner_user_id { format!("{}_{}", uid, req_id) } else { req_id.clone() };
    if let Ok(bytes) = serde_json::to_vec(&request) {
        let _ = store.put(save_key, bytes.into()).await;
    }

    Ok(Json(serde_json::json!({"status": "denied"})))
}

/// GET /.well-known/skills.json — Unified Skill Registry (Phase 2).
///
/// Aggregates skills from:
/// 1. connector_mcp_server (MCP tools via HTTP)
/// 2. native_skill_executor (Claw skills via HTTP)
///
/// Returns a unified registry for agent discovery and policy matching.
pub async fn skills_registry_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
) -> Json<serde_json::Value> {
    let client = shared.http_client.clone();

    // 1. Fetch MCP tools from connector_mcp_server
    let connector_url = &shared.config.connector_mcp_url;
    let mcp_tools = match client.get(format!("{}/tools/list", connector_url)).send().await {
        Ok(res) if res.status().is_success() => {
            res.json::<serde_json::Value>().await.unwrap_or(serde_json::json!([]))
        }
        _ => serde_json::json!([]),
    };

    // 2. Fetch Claw skills from local manifests (if professional/entreprise) or HTTP fallback
    let mut claw_skills = Vec::new();
    let is_professional = std::env::var("PROFESSIONAL_EDITION").unwrap_or_default() == "true";
    let mut loaded_local = false;

    if is_professional {
        // Try to load professional skills from directory
        // The host runs from lianxi-community/agent_in_a_box/host/
        let prof_dir = concat!("lianxi-", "professional");
        let path1 = format!("../../../{}/skills/data_analyst", prof_dir);
        let path2 = format!("../../{}/skills/data_analyst", prof_dir);
        let path3 = format!("{}/skills/data_analyst", prof_dir);
        let paths = [&path1, &path2, &path3];
        for path_str in &paths {
            let path = std::path::Path::new(path_str);
            if path.exists() && path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let dir = entry.path();
                        if dir.is_dir() {
                            let manifest_path = dir.join("manifest.json");
                            if manifest_path.exists() {
                                if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                                    if let Ok(mut skill_val) = serde_json::from_str::<serde_json::Value>(&content) {
                                        // Inject executor_type and category/bundle if they don't exist
                                        if let Some(obj) = skill_val.as_object_mut() {
                                            obj.entry("executor_type".to_string()).or_insert_with(|| serde_json::json!("sandboxed-skill"));
                                            obj.entry("category".to_string()).or_insert_with(|| serde_json::json!("data_analyst"));
                                            // Ensure inputSchema or input_schema is populated for the UI
                                            if !obj.contains_key("inputSchema") && !obj.contains_key("input_schema") {
                                                obj.insert("input_schema".to_string(), serde_json::json!({
                                                    "type": "object",
                                                    "properties": {
                                                        "dataset": {
                                                            "type": "string",
                                                            "description": "Name of the target dataset"
                                                        }
                                                    },
                                                    "required": ["dataset"]
                                                }));
                                            }
                                        }
                                        claw_skills.push(skill_val);
                                        loaded_local = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if loaded_local {
                break;
            }
        }
    }

    if !loaded_local {
        let executor_url = &shared.config.skill_executor_url;
        claw_skills = match client.get(format!("{}/skills", executor_url)).send().await {
            Ok(res) if res.status().is_success() => {
                res.json::<serde_json::Value>().await.unwrap_or(serde_json::json!([]))
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        };
    }

    // 3. Build unified registry
    let mcp_count = mcp_tools.as_array().map(|a| a.len()).unwrap_or(0);
    let claw_count = claw_skills.len();

    tracing::info!("📋 Skill registry: {} MCP tools, {} Claw skills (local={})", mcp_count, claw_count, loaded_local);

    Json(serde_json::json!({
        "version": "1.0",
        "host_id": shared.config.tenant_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "mcp_tools": mcp_tools,
        "claw_skills": claw_skills,
        "total_skills": mcp_count + claw_count,
    }))
}


pub async fn send_ledgerless_request_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(payload): Json<crate::dto::SendLedgerlessRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user_id = claims.user_id;

    // Bug 001 Fix: Normally a did:peer should be created for ledgerless connections.
    // We create a new throwaway identity in the vault via CreatePeerIdentity.
    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::CreatePeerIdentity(user_id.clone(), tx)).await;
    let peer_did = rx.await.unwrap_or_default();
    if peer_did.is_empty() {
        tracing::error!("❌ Failed to create peer identity for ledgerless request");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // REMOVED SetActiveDid here. We should NEVER forcibly switch the user's active DID
    // to a throwaway did:peer. Doing so breaks Contacts and other DID-linked portal features.

    tracing::info!("🤝 Generated and Activated Peer DID for ledgerless request: {}", peer_did);

    // Build the DID document so the recipient can resolve us back
    let did_doc_json = match build_complete_did_document(shared.clone(), &peer_did).await {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!("❌ Failed to build DID Document for peer DID: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let now_str = chrono::Utc::now().to_rfc3339();

    // Store the OUTGOING request locally. 
    // owner: throwaway_did (who we represent here)
    // sender: target_did (who we are sending TO)
    if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("contact_requests")) {
        let req_id = uuid::Uuid::new_v4().to_string();
        let pending_req = crate::dto::ContactRequest {
            id: req_id.clone(),
            owner_did: peer_did.clone(), 
            sender_did: payload.target_did.clone(),
            role: Some("OUTGOING".to_string()),
            request_msg: serde_json::json!({ 
                "message": payload.message,
                "did_document": did_doc_json 
            }),
            status: "PENDING".to_string(),
            created_at: now_str,
        };
        if let Ok(bytes) = serde_json::to_vec(&pending_req) {
            let _ = kv.put(req_id, bytes.into()).await;
        }
    }

    // Wrap the request message to include the DID document
    let body_json = serde_json::json!({
        "message": payload.message,
        "did_document": did_doc_json
    });

    match process_send_message_logic(shared, user_id, Some(peer_did), payload.target_did, body_json.to_string(), "https://lianxi.io/protocols/contact/1.0/request".to_string(), None).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            tracing::error!("❌ Ledgerless Send message error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn generate_did_web_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(payload): Json<crate::dto::GenerateDidWebRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await.map_err(|_| StatusCode::UNAUTHORIZED)?;

    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::CreateIdentity(claims.user_id.clone(), tx)).await;
    let generated_did = rx.await.unwrap_or_default();

    let did_web_id = format!("did:web:{}", payload.domain);
    let did_doc = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did_web_id,
        "verificationMethod": [{
            "id": format!("{}#keys-1", did_web_id),
            "type": "Ed25519VerificationKey2020",
            "controller": did_web_id,
            "publicKeyMultibase": generated_did.replace("did:twin:", "z")
        }],
        "service": [{
            "id": format!("{}#messaging", did_web_id),
            "type": "TwinMediatorInbox",
            "serviceEndpoint": format!("{}/twin/v1/messages", shared.config.gateway_url.as_deref().unwrap_or("https://gateway.lianxi.io"))
        }]
    });

    Ok(Json(did_doc))
}

#[cfg(feature = "messaging")]
pub async fn get_b2b_policies_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _claims = extract_claims(&shared, &headers).await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    let mut policies = Vec::new();

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("B2B_POLICIES") {
            use futures::StreamExt;
            if let Ok(mut keys) = store.keys().await {
                while let Some(Ok(key)) = keys.next().await {
                    if let Ok(Some(entry)) = store.get(&key).await {
                        if let Ok(prompt) = String::from_utf8(entry.to_vec()) {
                            policies.push(serde_json::json!({
                                "partner_did": key,
                                "prompt": prompt
                            }));
                        }
                    }
                }
            }
        }
    }
    Ok(Json(serde_json::json!({ "policies": policies })))
}

#[cfg(feature = "messaging")]
#[derive(serde::Deserialize)]
pub struct UpdateB2bPolicyRequest {
    pub partner_did: String,
    pub prompt: String,
}

#[cfg(feature = "messaging")]
pub async fn update_b2b_policy_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateB2bPolicyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _claims = extract_claims(&shared, &headers).await.map_err(|_| StatusCode::UNAUTHORIZED)?;

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("B2B_POLICIES") {
            let bytes = payload.prompt.as_bytes().to_vec();
            match store.put(payload.partner_did.clone(), bytes.into()).await {
                Ok(_) => {
                    tracing::info!("✅ B2B Policy updated for {}", payload.partner_did);
                    return Ok(Json(serde_json::json!({ "status": "success" })));
                }
                Err(e) => {
                    tracing::error!("❌ Failed to update B2B policy: {}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
    }
    Err(StatusCode::INTERNAL_SERVER_ERROR)
}
