//! WebSocket relay for live wallet connections.
//!
//! Wallets connect via `/ws/wallet`, authenticate with DID-Auth,
//! and receive real-time pushed messages. Offline messages are
//! drained from the blind mailbox on connect.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use axum::{
    extract::{State, ws::{WebSocket, WebSocketUpgrade, Message}},
    response::IntoResponse,
};
use futures::{StreamExt, SinkExt};
use serde::{Deserialize, Serialize};
use async_nats::jetstream::Context as JsContext;
use base64::Engine;

use crate::blind_mailbox;

/// A connected wallet session.
#[derive(Debug, Clone)]
pub struct WalletSession {
    /// The pairwise DID this wallet authenticated as
    pub pairwise_did: String,
    /// Channel to send messages to this wallet
    pub tx: mpsc::UnboundedSender<String>,
}

/// Thread-safe registry of connected wallet sessions.
pub type WalletSessions = Arc<Mutex<HashMap<String, WalletSession>>>;

/// Create a new empty wallet sessions registry.
pub fn new_sessions() -> WalletSessions {
    Arc::new(Mutex::new(HashMap::new()))
}

/// DID-Auth challenge sent to wallet on WebSocket open.
#[derive(Debug, Serialize)]
pub struct AuthChallenge {
    pub challenge: String,
    pub gateway_did: String,
    pub timestamp: i64,
}

/// DID-Auth response from wallet.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub pairwise_did: String,
    pub signature: String,  // hex-encoded Ed25519 signature of challenge
    pub public_key: String, // hex-encoded 32-byte Ed25519 public key
}

/// Message pushed to wallet via WebSocket.
#[derive(Debug, Serialize)]
pub struct WalletPush {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub payload: serde_json::Value,
}

/// Try to push a message to an online wallet. Returns true if delivered.
pub async fn try_push_to_wallet(
    sessions: &WalletSessions,
    pairwise_did: &str,
    encrypted_payload: &str,
) -> bool {
    let sessions_lock = sessions.lock().await;
    if let Some(session) = sessions_lock.get(pairwise_did) {
        let push = WalletPush {
            msg_type: "didcomm".to_string(),
            payload: serde_json::json!({ "envelope": encrypted_payload }),
        };
        if let Ok(json) = serde_json::to_string(&push) {
            if session.tx.send(json).is_ok() {
                tracing::info!("📲 Pushed message to online wallet: {}…", &pairwise_did[..20.min(pairwise_did.len())]);
                return true;
            }
        }
    }
    false
}

/// Axum handler for WebSocket upgrade at `/ws/wallet`.
pub async fn wallet_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<crate::GatewayAppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_wallet_connection(socket, state))
}

/// Handle a single wallet WebSocket connection lifecycle.
async fn handle_wallet_connection(socket: WebSocket, state: crate::GatewayAppState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    
    // 1. Generate and send DID-Auth challenge
    let challenge = uuid::Uuid::new_v4().to_string();
    let auth_challenge = AuthChallenge {
        challenge: challenge.clone(),
        gateway_did: "did:twin:gateway".to_string(),  // TODO: use actual gateway DID
        timestamp: chrono::Utc::now().timestamp(),
    };
    
    let challenge_json = serde_json::to_string(&auth_challenge).unwrap();
    if ws_sender.send(Message::Text(challenge_json.into())).await.is_err() {
        tracing::warn!("❌ Failed to send DID-Auth challenge");
        return;
    }

    // 2. Wait for DID-Auth response (5 second timeout)
    let auth_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ws_receiver.next(),
    ).await;

    let auth_response: AuthResponse = match auth_result {
        Ok(Some(Ok(Message::Text(text)))) => {
            match serde_json::from_str(&text) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("❌ Invalid DID-Auth response: {}", e);
                    let _ = ws_sender.send(Message::Text(r#"{"error":"invalid_auth"}"#.into())).await;
                    return;
                }
            }
        }
        _ => {
            tracing::warn!("❌ DID-Auth timeout or connection closed");
            return;
        }
    };

    // 3. Verify Ed25519 signature
    let verified = verify_did_auth(&challenge, &auth_response);
    if !verified {
        tracing::warn!("❌ DID-Auth signature verification failed for {}", auth_response.pairwise_did);
        let _ = ws_sender.send(Message::Text(r#"{"error":"auth_failed"}"#.into())).await;
        return;
    }

    let pairwise_did = auth_response.pairwise_did.clone();
    tracing::info!("✅ Wallet authenticated: {}", pairwise_did);

    // 4. Send auth success
    let _ = ws_sender.send(Message::Text(
        serde_json::json!({"status": "authenticated", "did": &pairwise_did}).to_string().into()
    )).await;

    // 4b. Publish Wallet DID to DHT for discovery
    if let Some(js) = &state.jetstream {
        let did_clone = pairwise_did.clone();
        let pk_clone = auth_response.public_key.clone();
        let js_clone = js.clone();
        tokio::spawn(async move {
            if let Err(e) = publish_wallet_did(&js_clone, &did_clone, &pk_clone).await {
                tracing::warn!("⚠️ Failed to auto-publish Wallet DID: {}", e);
            }
        });
    }

    // 4b. Publish Wallet DID to DHT for discovery
    if let Some(js) = &state.jetstream {
        let did_clone = pairwise_did.clone();
        let pk_clone = auth_response.public_key.clone();
        let js_clone = js.clone();
        tokio::spawn(async move {
            if let Err(e) = publish_wallet_did(&js_clone, &did_clone, &pk_clone).await {
                tracing::warn!("⚠️ Failed to auto-publish Wallet DID: {}", e);
            }
        });
    }

    // 5. Drain blind mailbox and push pending messages
    if let Some(js) = &state.jetstream {
        match blind_mailbox::drain_mailbox(js, &pairwise_did, &state.gateway_seed).await {
            Ok(messages) if !messages.is_empty() => {
                tracing::info!("📬 Draining {} offline messages for {}", messages.len(), &pairwise_did);
                for msg in messages {
                    let push = WalletPush {
                        msg_type: "mailbox_drain".to_string(),
                        payload: serde_json::json!({ 
                            "id": msg.id,
                            "envelope": msg.encrypted_payload,
                            "stored_at": msg.stored_at
                        }),
                    };
                    if let Ok(json) = serde_json::to_string(&push) {
                        if ws_sender.send(Message::Text(json.into())).await.is_err() {
                            break; // Connection lost during drain
                        }
                    }
                }
            }
            Ok(_) => {} // No pending messages
            Err(e) => tracing::warn!("⚠️ Failed to drain mailbox: {}", e),
        }
    }

    // 6. Register session for live pushes
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let mut sessions = state.wallet_sessions.lock().await;
        sessions.insert(pairwise_did.clone(), WalletSession {
            pairwise_did: pairwise_did.clone(),
            tx,
        });
        tracing::info!("📡 Registered wallet session: {} (total: {})", pairwise_did, sessions.len());
    }

    // 7. Bidirectional message loop
    let did_for_cleanup = pairwise_did.clone();
    let sessions_for_cleanup = state.wallet_sessions.clone();
    
    loop {
        tokio::select! {
            // Messages from other parts of the system → push to wallet
            Some(outgoing) = rx.recv() => {
                if ws_sender.send(Message::Text(outgoing.into())).await.is_err() {
                    break; // Connection lost
                }
            }
            // Messages from wallet → handle (heartbeat, etc.)
            Some(incoming) = ws_receiver.next() => {
                match incoming {
                    Ok(Message::Ping(data)) => {
                        let _ = ws_sender.send(Message::Pong(data)).await;
                    }
                    Ok(Message::Close(_)) => break,
                    Ok(Message::Text(text)) => {
                        // Handle wallet→host commands (like ActionResponse)
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(msg_type) = value.get("type").and_then(|t| t.as_str()) {
                                if msg_type == "action_response" {
                                    if let Some(payload) = value.get("payload") {
                                        if let Some(js) = &state.jetstream {
                                            tracing::info!("📩 Forwarding ActionResponse from Wallet to NATS...");
                                            let nats_payload = serde_json::to_vec(payload).unwrap_or_default();
                                            // We publish to the replies topic. The Host can subscribe to it.
                                            let _ = js.publish("mcp.escalate.replies".to_string(), nats_payload.into()).await;
                                        }
                                    }
                                } else if msg_type == "didcomm_send" {
                                    // 1. Extract fields
                                    if let (Some(to_did), Some(body), Some(inner_type), Some(from_did)) = (
                                        value.get("to").and_then(|v| v.as_str()),
                                        value.get("body").and_then(|v| v.as_str()),
                                        value.get("msg_type").and_then(|v| v.as_str()),
                                        value.get("from").and_then(|v| v.as_str())
                                    ) {
                                        tracing::info!("📩 Wallet wants to send DIDComm message to {}", to_did);
                                        
                                        // 2. Resolve recipient from DHT
                                        if let Some(js) = &state.jetstream {
                                            let to_did_clone = to_did.to_string();
                                            let body_clone = body.to_string();
                                            let inner_type_clone = inner_type.to_string();
                                            let from_did_clone = from_did.to_string();
                                            let js_clone = js.clone();
                                            let gateway_seed_clone = state.gateway_seed.clone();
                                            
                                            tokio::spawn(async move {
                                                if let Ok(kv) = js_clone.get_key_value("dht_discovery").await {
                                                    let blind_id = crate::generate_blind_pointer(&to_did_clone);
                                                    if let Ok(Some(entry)) = kv.get(&blind_id).await {
                                                        if let Ok(stored) = serde_json::from_slice::<serde_json::Value>(&entry) {
                                                            let doc = stored.get("document").unwrap_or(&stored);
                                                            
                                                            // 3. Extract recipient public key and service endpoint
                                                            let mut recipient_pub_key = None;
                                                            if let Some(vms) = doc.get("verificationMethod").and_then(|v| v.as_array()) {
                                                                for vm in vms {
                                                                    if let Some(b64) = vm.get("publicKeyBase64").and_then(|v| v.as_str()) {
                                                                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                                                                            if bytes.len() == 32 {
                                                                                let mut arr = [0u8; 32];
                                                                                arr.copy_from_slice(&bytes);
                                                                                recipient_pub_key = Some(arr);
                                                                                break;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            
                                                            let mut endpoint_uri = None;
                                                            let mut target_id = None;
                                                            if let Some(services) = doc.get("service").and_then(|v| v.as_array()) {
                                                                for svc in services {
                                                                    if svc.get("type").and_then(|v| v.as_str()) == Some("MessagingService") {
                                                                        if let Some(ep) = svc.get("serviceEndpoint") {
                                                                            if let Some(s) = ep.as_str() {
                                                                                endpoint_uri = Some(s.to_string());
                                                                            } else if let Some(obj) = ep.as_object() {
                                                                                if let Some(u) = obj.get("uri").and_then(|v| v.as_str()) {
                                                                                    endpoint_uri = Some(u.to_string());
                                                                                }
                                                                                if let Some(t) = obj.get("target_id").and_then(|v| v.as_str()) {
                                                                                    target_id = Some(t.to_string());
                                                                                }
                                                                            }
                                                                        }
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                            
                                                            // 4. Construct DIDComm inner message
                                                            let msg_id = uuid::Uuid::new_v4().to_string();
                                                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                                            let inner_msg = serde_json::json!({
                                                                "id": msg_id,
                                                                "type": inner_type_clone,
                                                                "from": from_did_clone,
                                                                "to": [to_did_clone],
                                                                "body": body_clone,
                                                                "created_time": now
                                                            });
                                                            
                                                            // 5. Encrypt (or fallback to plain if no key)
                                                            let payload_to_send = if let Some(_pubkey) = recipient_pub_key {
                                                                // In the hybrid architecture, E2E encryption happens at the edges (Host/Wallet) via OpenMLS.
                                                                // The gateway simply routes the opaque payload it receives.
                                                                tracing::info!("🔒 Relaying message for {} (E2E encryption handled by endpoints)", to_did_clone);
                                                                serde_json::to_string(&inner_msg).unwrap()
                                                            } else {
                                                                tracing::warn!("⚠️ No public key found for recipient, sending unencrypted (should not happen in prod)");
                                                                serde_json::to_string(&inner_msg).unwrap()
                                                            };
                                                            
                                                            // 6. Route the message
                                                            if let Some(tid) = target_id {
                                                                // Decrypt internal opaque token
                                                                if let Ok(blob_bytes) = base64::engine::general_purpose::STANDARD.decode(&tid) {
                                                                    if blob_bytes.len() > 24 {
                                                                        use hkdf::Hkdf;
                                                                        use sha2::Sha256;
                                                                        use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit}};
                                                                        
                                                                        let nonce = XNonce::from_slice(&blob_bytes[..24]);
                                                                        let ciphertext = &blob_bytes[24..];
                                                                        
                                                                        let hk_wrap = Hkdf::<Sha256>::new(None, &gateway_seed_clone);
                                                                        let mut key_bytes = [0u8; 32];
                                                                        if hk_wrap.expand(b"sovereign:gateway:internal-wrap", &mut key_bytes).is_ok() {
                                                                            let key = chacha20poly1305::Key::from_slice(&key_bytes);
                                                                            let cipher_wrap = XChaCha20Poly1305::new(key);
                                                                            if let Ok(dec_bytes) = cipher_wrap.decrypt(nonce, ciphertext) {
                                                                                if let Ok(subject_str) = String::from_utf8(dec_bytes) {
                                                                                    let nats_subject = format!("v1.{}", subject_str);
                                                                                    tracing::info!("📤 Relaying Wallet message to JIT NATS subject: {}", nats_subject);
                                                                                    let _ = js_clone.publish(nats_subject, payload_to_send.into()).await;
                                                                                    return;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            
                                                            if let Some(uri) = endpoint_uri {
                                                                if uri != "http://localhost:3002/ingress" && !uri.contains("gateway.push.wallet") {
                                                                    tracing::info!("🌐 Sending Wallet message to external HTTP endpoint: {}", uri);
                                                                    let client = reqwest::Client::new();
                                                                    if let Err(e) = client.post(&uri).body(payload_to_send).send().await {
                                                                        tracing::warn!("⚠️ Failed to send to external endpoint: {}", e);
                                                                    }
                                                                    return;
                                                                }
                                                            }
                                                            
                                                            // Fallback naive routing if all else fails
                                                            use sha2::{Digest, Sha256};
                                                            let mut hasher = Sha256::new();
                                                            hasher.update((to_did_clone.clone() + "sovereign_local_subject").as_bytes());
                                                            // Fallback naive routing
                                                            let hashed_subject = hex::encode(hasher.finalize());
                                                            let nats_subject = format!("v1.{}", hashed_subject);
                                                            
                                                            tracing::info!("📤 Relaying Wallet message to NATS via fallback: {}", nats_subject);
                                                            let _ = js_clone.publish(nats_subject, payload_to_send.into()).await;
                                                        }
                                                    } else {
                                                        tracing::error!("❌ Recipient DID {} not found in DHT", to_did_clone);
                                                    }
                                                }
                                            });
                                        }
                                    }
                                } else {
                                    tracing::debug!("📩 Unknown Wallet message: {}…", &text[..text.len().min(50)]);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                    _ => {}
                }
            }
            // Heartbeat timeout (30s of no activity → disconnect)
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if ws_sender.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    // 8. Cleanup on disconnect
    {
        let mut sessions = sessions_for_cleanup.lock().await;
        sessions.remove(&did_for_cleanup);
        tracing::info!("🔌 Wallet disconnected: {} (remaining: {})", did_for_cleanup, sessions.len());
    }
}

/// Verify a DID-Auth Ed25519 signature.
fn verify_did_auth(challenge: &str, response: &AuthResponse) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    
    let pub_bytes = match hex::decode(&response.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(&response.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pub_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);

    // Verify: signature of the challenge string
    verifying_key.verify(challenge.as_bytes(), &signature).is_ok()
}

/// Publish a Wallet's pairwise DID and its service endpoint to the DHT.
/// This allows the Host to discover the return path for replies.
async fn publish_wallet_did(
    js: &async_nats::jetstream::Context,
    did: &str,
    pk_hex: &str,
) -> anyhow::Result<()> {
    let kv = js.get_key_value("dht_discovery").await?;
    
    // Convert hex public key to Base64 for the DID document
    let pk_bytes = hex::decode(pk_hex)?;
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk_bytes);

    let did_doc = serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#routing-key", did),
            "type": "X25519KeyAgreementKey2019", // Standard for DIDComm
            "controller": did,
            "publicKeyBase64": pk_b64
        }],
        "service": [{
            "id": format!("{}#messaging", did),
            "type": "MessagingService",
            "serviceEndpoint": "http://localhost:3002/ws/wallet" // Special endpoint for Host discovery
        }]
    });

    let blind_id = crate::generate_blind_pointer(did);
    let entry = serde_json::json!({
        "document": did_doc,
        "published_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
    });

    kv.put(blind_id, serde_json::to_vec(&entry)?.into()).await?;
    tracing::info!("📢 Published Wallet DID Document to DHT for discovery: {}", did);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_did_auth_valid_signature() {
        use ed25519_dalek::{SigningKey, Signer};
        
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let challenge = "test-challenge-123";
        let signature = signing_key.sign(challenge.as_bytes());
        
        let response = AuthResponse {
            pairwise_did: "did:twin:zTest".to_string(),
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        };

        assert!(verify_did_auth(challenge, &response));
    }

    #[test]
    fn test_verify_did_auth_wrong_challenge() {
        use ed25519_dalek::{SigningKey, Signer};
        
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let signature = signing_key.sign(b"different-challenge");
        
        let response = AuthResponse {
            pairwise_did: "did:twin:zTest".to_string(),
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        };

        assert!(!verify_did_auth("test-challenge-123", &response));
    }

    #[test]
    fn test_verify_did_auth_invalid_key() {
        let response = AuthResponse {
            pairwise_did: "did:twin:zTest".to_string(),
            signature: "00".repeat(64),
            public_key: "badkey".to_string(),
        };
        assert!(!verify_did_auth("challenge", &response));
    }

    #[tokio::test]
    async fn test_try_push_to_wallet_no_session() {
        let sessions = new_sessions();
        let result = try_push_to_wallet(&sessions, "did:twin:zNotConnected", "payload").await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_try_push_to_wallet_active_session() {
        let sessions = new_sessions();
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        {
            let mut s = sessions.lock().await;
            s.insert("did:twin:zTest".to_string(), WalletSession {
                pairwise_did: "did:twin:zTest".to_string(),
                tx,
            });
        }

        let result = try_push_to_wallet(&sessions, "did:twin:zTest", "encrypted_data").await;
        assert!(result);
        
        // Verify message was received
        let msg = rx.recv().await.unwrap();
        assert!(msg.contains("encrypted_data"));
    }
}
