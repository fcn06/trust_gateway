use std::collections::HashMap;
use std::sync::Arc;
use axum::{
    extract::{State, Json, Path as AxumPath, Query},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
// use serde_json::Value;
use tokio::sync::oneshot;
use anyhow::Result;
use futures::StreamExt;

#[derive(Deserialize)]
pub struct AuditExportParams {
    pub limit: Option<usize>,
}


use crate::shared_state::WebauthnSharedState;
use crate::commands::{VaultCommand, AclCommand, ContactStoreCommand};
pub use crate::dto::*;
use crate::auth::{extract_claims, resolve_active_did_for_user};
use crate::logic::{compute_local_subject, generate_blind_pointer, publish_to_dht, resolve_did_document_from_dht};
use crate::sovereign::gateway::common_types::MlsMessage;
// use async_nats::jetstream::kv::Entry;



// --- Logic Functions ---

pub async fn handle_incoming_message_bypass_logic(
    state: &WebauthnSharedState,
    owner_did: &String,
    msg: &MlsMessage,
    envelope: &Option<String>,
) -> bool {
    let sender = &msg.sender_target_id;
    tracing::info!("🔍 [BYPASS CHECK] Group: {}, Recipient: {}, From: {}, Type: '{}'", msg.group_id, owner_did, sender, msg.content_type);
    
    if owner_did.is_empty() || owner_did == "None" {
        tracing::warn!("⚠️ [BYPASS] Owner DID is invalid ('{}'), skipping bypass logic", owner_did);
        return false;
    }

    // 1. Handle invitation_accepted
    if msg.content_type == "https://didcomm.org/invitation/1.0/accepted" {
        tracing::info!("🔓 [BYPASS] Bypassing ACL for invitation_accepted from {}", sender);
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let policy = crate::sovereign::gateway::common_types::ConnectionPolicy {
            did: sender.to_string(),
            alias: format!("Contact {}", &sender[..12.min(sender.len())]),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
            permissions: vec![
                crate::sovereign::gateway::common_types::Permission::Chat, 
                crate::sovereign::gateway::common_types::Permission::Discovery
            ],
            status: crate::sovereign::gateway::common_types::ConnectionStatus::Active,
        };
        
        let _ = state.acl_cmd_tx.send(AclCommand::UpdatePolicy {
            owner: owner_did.clone(),
            policy,
            resp: resp_tx,
        }).await;
        let _ = resp_rx.await;
        
        // Forward to messaging task so it shows in UI
        let _ = state.messaging_cmd_tx.send(IncomingMessage { msg: msg.clone(), envelope: envelope.clone() }).await;
        return true;
    }

    // 2. Handle contact/1.0/request -> Store as PENDING (with deduplication)
    if msg.content_type == "https://lianxi.io/protocols/contact/1.0/request" {
        tracing::info!("📨 [BYPASS] Received Contact Request from {}", sender);
        if let Some(kv) = state.kv_stores.as_ref().and_then(|m| m.get("contact_requests")) {
             let body_str = String::from_utf8_lossy(&msg.ciphertext).to_string();
             let body_json: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(serde_json::json!({ "body": body_str }));

             // Bug 002 Fix: Deduplication — check if a PENDING request from the same sender already exists
             let mut already_exists = false;
             if let Ok(mut keys_iter) = kv.keys().await {
                 while let Some(key_result) = keys_iter.next().await {
                     let key = match key_result {
                         Ok(k) => k,
                         Err(_) => continue,
                     };
                     if let Ok(Some(entry)) = kv.get(&key).await {
                         if let Ok(existing) = serde_json::from_slice::<ContactRequest>(&entry) {
                             if existing.sender_did == *sender
                                 && existing.owner_did == *owner_did
                                 && existing.status == "PENDING"
                                 && existing.role.as_deref() == Some("INCOMING")
                             {
                                 tracing::info!("⏭️ [BYPASS] Duplicate contact request from {} — skipping", sender);
                                 already_exists = true;
                                 break;
                             }
                         }
                     }
                 }
             }

             if already_exists {
                 return true;
             }

             // --- LEDGERLESS SUPPORT: Extract and Store Peer DID Document ---
             // If this is a ledgerless request, the sender DID document might be in the 'did_document' field.
             if let Some(did_doc_val) = body_json.get("did_document") {
                 if let Ok(did_doc) = serde_json::from_value::<crate::sovereign::gateway::common_types::DidDocument>(did_doc_val.clone()) {
                     tracing::info!("📇 [BYPASS] Extracting Peer DID Document for {}", sender);
                     let (cs_tx, _cs_rx) = tokio::sync::oneshot::channel();
                     let _ = state.contact_cmd_tx.send(ContactStoreCommand::StoreContact {
                         did_doc,
                         resp: cs_tx,
                     }).await;
                     // We don't necessarily need to wait for store confirmation to continue the bypass flow
                 }
             }

             let req_id = uuid::Uuid::new_v4().to_string();
             let req = ContactRequest {
                 id: req_id.clone(),
                 owner_did: owner_did.clone(),
                 sender_did: sender.to_string(),
                 role: Some("INCOMING".to_string()),
                 request_msg: body_json,
                 status: "PENDING".to_string(),
                 created_at: chrono::Utc::now().to_rfc3339(),
             };
             if let Ok(_) = kv.put(req_id.clone(), serde_json::to_vec(&req).unwrap().into()).await {
                 tracing::info!("💾 Stored PENDING Contact Request (ID: {}) for owner {}", req.id, owner_did);
                 return true;
             } else {
                 tracing::error!("❌ [BYPASS] Failed to store Contact Request in KV");
             }
        }
    }

    // 3. Handle contact/1.0/acceptance-response -> Auto-ACL + Update OUTGOING request
    if msg.content_type == "https://lianxi.io/protocols/contact/1.0/acceptance-response" {
         tracing::info!("✅ [BYPASS] Received Contact Request Acceptance from {}", sender);

         // --- LEDGERLESS SUPPORT: Extract and Store Accepter's DID Document ---
         let body_str = String::from_utf8_lossy(&msg.ciphertext).to_string();
         if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(&body_str) {
             if let Some(did_doc_val) = body_json.get("did_document") {
                 if let Ok(did_doc) = serde_json::from_value::<crate::sovereign::gateway::common_types::DidDocument>(did_doc_val.clone()) {
                     tracing::info!("📇 [BYPASS] Storing Accepter's DID Document for {}", sender);
                     let (cs_tx, _cs_rx) = tokio::sync::oneshot::channel();
                     let _ = state.contact_cmd_tx.send(ContactStoreCommand::StoreContact {
                         did_doc,
                         resp: cs_tx,
                     }).await;
                 }
             }
         }

         let policy = crate::sovereign::gateway::common_types::ConnectionPolicy {
            did: sender.to_string(),
            alias: format!("Contact {}", &sender[..12.min(sender.len())]),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
            permissions: vec![
                crate::sovereign::gateway::common_types::Permission::Chat, 
                crate::sovereign::gateway::common_types::Permission::Discovery
            ],
            status: crate::sovereign::gateway::common_types::ConnectionStatus::Active,
        };
        
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let _ = state.acl_cmd_tx.send(AclCommand::UpdatePolicy {
            owner: owner_did.clone(),
            policy,
            resp: resp_tx,
        }).await;
        let _ = resp_rx.await;

        // Bug 004 Fix: Update the OUTGOING contact request from PENDING to ACCEPTED
        if let Some(kv) = state.kv_stores.as_ref().and_then(|m| m.get("contact_requests")) {
            if let Ok(mut keys_iter) = kv.keys().await {
                while let Some(key_result) = keys_iter.next().await {
                    let key = match key_result {
                        Ok(k) => k,
                        Err(_) => continue,
                    };
                    if let Ok(Some(entry)) = kv.get(&key).await {
                        if let Ok(mut existing) = serde_json::from_slice::<ContactRequest>(&entry) {
                            // Note: For OUTGOING, sender_did is the TARGET (recipient)
                            if existing.sender_did == *sender
                                && existing.owner_did == *owner_did
                                && existing.status == "PENDING"
                                && existing.role.as_deref() == Some("OUTGOING")
                            {
                                existing.status = "ACCEPTED".to_string();
                                let _ = kv.put(key.clone(), serde_json::to_vec(&existing).unwrap().into()).await;
                                tracing::info!("✅ [BYPASS] Updated OUTGOING contact request {} to ACCEPTED", &key);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Forward as message so they see "Contact Request Accepted" in chat
        let _ = state.messaging_cmd_tx.send(IncomingMessage { msg: msg.clone(), envelope: envelope.clone() }).await;
        return true;
    }

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
    // 0. Sanitize recipient DID (handle copy-paste artifacts like tabs or "y ")
    let recipient = if let Some(idx) = recipient.find("did:") {
        recipient[idx..].trim().to_string()
    } else {
        recipient.trim().to_string()
    };
    
    // 1. Resolve all user DIDs to verify ownership
    let (tx_l, rx_l) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id.clone(), tx_l)).await;
    let my_dids = rx_l.await.unwrap_or_default();
    
    let sender_did = if let Some(fd) = from_did {
        if !my_dids.contains(&fd) {
            // Peer DIDs are not in the main identity list (to keep UI clean),
            // but they have a reverse mapping did_user:{did} -> user_id.
            // Check this reverse mapping before rejecting.
            let (resolve_tx, resolve_rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::ResolveDid { did: fd.clone(), resp: resolve_tx }).await;
            let owner = resolve_rx.await.ok().flatten();
            if owner.as_deref() != Some(&user_id) {
                return Err("Unauthorized: You do not own this sender DID".to_string());
            }
        }
        fd
    } else {
        // Fallback to active DID if not specified
        resolve_active_did_for_user(shared.clone(), &user_id).await.map_err(|_| "DID not found".to_string())?
    };
    
    // Debug: Log sender and recipient DIDs for comparison
    tracing::info!("📧 Send message: sender_did='{}' recipient='{}'", &sender_did, &recipient);
    
    if typ == "https://didcomm.org/message/2.0/self_service" && sender_did != recipient {
        return Err("Forbidden: self-service must be to self".to_string());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // In the hybrid architecture, messages are constructed as MlsMessage and sent
    // via the gateway. MLS encryption is handled by the mls_session component.
    let msg_id = uuid::Uuid::new_v4().to_string();
    let final_thid = thid.clone().unwrap_or_else(|| msg_id.clone());

    // --- V5 Agent Delegation Intercept ---
    // Check if recipient is one of the user's own DIDs (covers multi-DID self-chat)
    let is_self_message_for_agent = sender_did == recipient || my_dids.contains(&recipient);
    if (typ == "https://didcomm.org/message/2.0/self_service" || 
        typ == "https://didcomm.org/self-note/1.0/note" || 
        (typ == "https://didcomm.org/message/2.0/chat" && is_self_message_for_agent)) && message.contains("@agent") {
        
        tracing::info!("🤖 '@agent' mention detected in message. Intercepting for delegation...");
        
        let shared_clone = shared.clone();
        let sender_clone = sender_did.clone();
        let user_clone = user_id.clone();
        let msg_clone = message.clone();
        let thid_to_pass = Some(final_thid.clone());
        
        tokio::spawn(async move {
            match crate::handlers::agent::dispatch_to_ssi_agent(
                shared_clone,
                &sender_clone,
                &user_clone,
                &msg_clone,
                false, // not institutional bypass for this self-service flow
                thid_to_pass,
            ).await {
                Ok(_) => {}, // self-note logic already handled inside agent.rs
                Err((status, err_msg)) => {
                    tracing::error!("Agent dispatch failed ({}): {}", status, err_msg);
                }
            }
        });
        
        if typ == "https://didcomm.org/message/2.0/self_service" {
            return Ok(serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "status": "delegated_to_agent"
            }));
        }
    }
    // -------------------------------------

    // Convert to DTO for local storage
    let dto = PlainDidcommDto {
        id: msg_id.clone(),
        r#type: typ.clone(),
        from: Some(sender_did.clone()),
        to: Some(vec![recipient.clone()]),
        thid: Some(final_thid),
        body: serde_json::from_str(&message).unwrap_or(serde_json::Value::String(message.clone())),
        created_time: Some(now),
        expires_time: None,
        status: Some("distributed".to_string()),
        envelope: None,
        alias: None,
    };

    let msg = crate::dto::map_dto_to_wit(dto.clone());
    
    let envelope = serde_json::to_string(&dto).map_err(|e| format!("JSON error: {}", e))?;
    
    let mut distributed_success = false;
    
    let is_self_message = sender_did == recipient;
    if is_self_message {
        tracing::info!("📝 Self-message detected, storing locally without DHT resolution");
        distributed_success = true;
    }
    
    tracing::info!("📤 Attempting to distribute message to recipient: {}", recipient);
    
    if !is_self_message {
        // --- LOCAL NATS SHORTCUT ---
        // If the recipient is on the same host, publish directly to NATS.
        let target_id = crate::logic::compute_local_subject(&recipient, &shared.house_salt);
        let is_local = if let Ok(map) = shared.target_id_map.lock() {
            map.contains_key(&target_id)
        } else { false };

        if is_local {
            if let Some(nc) = &shared.nats {
                let node_id = crate::logic::compute_node_id(&shared.house_salt);
                let subject = if shared.config.tenant_id.is_empty() {
                    format!("v1.{}.didcomm.{}", node_id, target_id)
                } else {
                    format!("v1.{}.{}.didcomm.{}", shared.config.tenant_id, node_id, target_id)
                };
                let _ = nc.publish(subject.clone(), envelope.clone().into()).await;
                distributed_success = true;
                tracing::info!("📢 Published to local NATS subject: {}", subject);
            }
        }

        // === Contact Store Resolution (Hybrid Architecture: Ledgerless) ===
        // Try the local contact_store first — DID Documents are exchanged directly during handshake.
        let (cs_tx, cs_rx) = oneshot::channel();
        let _ = shared.contact_cmd_tx.send(ContactStoreCommand::GetContact {
            did: recipient.clone(),
            resp: cs_tx,
        }).await;
        
        if let Ok(Some(did_doc)) = cs_rx.await {
            tracing::info!("📇 Resolved recipient from contact_store: {}", recipient);
            
            // Find the messaging service endpoint
            if let Some(svc) = did_doc.service_endpoints.iter().find(|s| s.type_ == "MessagingGateway" || s.type_ == "MessagingService" || s.type_ == "DIDCommMessaging") {
                let endpoint = &svc.endpoint;
                tracing::info!("📤 Sending via contact_store endpoint: {}", endpoint);
                
                let client = reqwest::Client::new();
                match client.post(endpoint).body(envelope.clone()).send().await {
                    Ok(res) if res.status().is_success() => {
                        distributed_success = true;
                        tracing::info!("✅ Sent via contact_store-resolved endpoint");
                    },
                    Ok(res) => tracing::error!("❌ Contact store endpoint returned: {}", res.status()),
                    Err(e) => tracing::error!("❌ Contact store endpoint error: {}", e),
                }
            } else {
                tracing::warn!("⚠️ Contact found but no MessagingGateway service endpoint");
            }
        } else {
            tracing::info!("📇 Recipient not in contact_store, falling back to DHT");
        }

        // === DHT Fallback (Legacy) ===
        if !distributed_success {
        if let Some(kv_stores) = &shared.kv_stores {
            if let Some(dht_store) = kv_stores.get("dht_discovery") {
                if let Some(doc) = resolve_did_document_from_dht(dht_store, &recipient).await {
                    tracing::info!("📄 Resolved DID Doc for routing");
                    if let Some(service) = doc["service"].as_array()
                        .and_then(|services| services.iter().find(|s| s["type"] == "MessagingService" || s["type"] == "DIDCommMessaging")) {
                        
                        let service_endpoint = &service["serviceEndpoint"];
                        
                        if let Some(endpoint_str) = service_endpoint.as_str() {
                            // --- Legacy / Direct Addressing ---
                            tracing::info!("Use legacy endpoint: {}", endpoint_str);
                            
                            // NEW: Check if this is a Wallet WebSocket endpoint
                            if endpoint_str.contains("/ws/wallet") {
                                if let Some(nc) = &shared.nats {
                                    // Wrap the envelope in the Gateway push format
                                    let push_payload = serde_json::json!({
                                        "recipient_did": recipient,
                                        "type": "chat_message",
                                        "envelope": envelope
                                    });
                                    if nc.publish("gateway.push.wallet".to_string(), serde_json::to_vec(&push_payload).unwrap().into()).await.is_ok() {
                                        distributed_success = true;
                                        tracing::info!("📤 Pushed DIDComm reply to online Wallet via Gateway WS");
                                    }
                                }
                            } else if endpoint_str.starts_with("nats://") {
                                let subject = endpoint_str.split('/').last().unwrap_or(endpoint_str);
                                if let Some(nc) = &shared.nats {
                                    match nc.publish(subject.to_string(), envelope.clone().into()).await {
                                        Ok(_) => {
                                            distributed_success = true;
                                            tracing::info!("📤 Sent via DHT-resolved NATS endpoint: {}", subject);
                                        },
                                        Err(e) => tracing::error!("❌ NATS Publish failed: {}", e),
                                    }
                                }
                            } else {
                                // HTTP endpoint
                                let client = reqwest::Client::new();
                                match client.post(endpoint_str).body(envelope.clone()).send().await {
                                    Ok(res) if res.status().is_success() => {
                                        distributed_success = true;
                                        tracing::info!("📤 Sent via DHT-resolved HTTP endpoint");
                                    },
                                    Ok(res) => tracing::error!("❌ HTTP Post failed with status: {}", res.status()),
                                    Err(e) => tracing::error!("❌ HTTP Post failed: {}", e),
                                }
                            }
                        } else if let Some(endpoint_obj) = service_endpoint.as_object() {
                            // --- JIT Routing (Resilient Coordination) ---
                            let uri = endpoint_obj.get("uri").and_then(|v| v.as_str()).unwrap_or_default();
                            let routing_did = endpoint_obj.get("routing_did").and_then(|v| v.as_str()).unwrap_or_default();
                            let target_id_blob = endpoint_obj.get("target_id").and_then(|v| v.as_str()).unwrap_or_default();

                            if !uri.is_empty() && !routing_did.is_empty() && !target_id_blob.is_empty() {
                                tracing::info!("🔏 Resolving Gateway DID: {}", routing_did);
                                // 1. Resolve Gateway Public Key from DHT
                                if let Some(gw_doc) = resolve_did_document_from_dht(dht_store, routing_did).await {
                                    let gw_pub_key = gw_doc["verificationMethod"].as_array()
                                        .and_then(|vms| vms.iter().find(|v| v["id"].as_str().unwrap_or_default().contains("routing-key")))
                                        .and_then(|vm| vm["publicKeyBase64"].as_str());

                                    if let Some(pub_key) = gw_pub_key {
                                        // 2. Generate Transient JIT Token via Vault
                                        let (tx_j, rx_j) = oneshot::channel();
                                        let _ = shared.vault_cmd_tx.send(VaultCommand::EncryptRoutingToken { 
                                            routing_key: pub_key.to_string(), 
                                            target_id: target_id_blob.to_string(), 
                                            resp: tx_j 
                                        }).await;

                                        match rx_j.await {
                                            Ok(Ok(token)) => {
                                                tracing::info!("🔒 JIT Encryption SUCCESS. Dispatching to: {}", uri);
                                                let client = reqwest::Client::new();
                                                
                                                // --- Control & Trace ---
                                                tracing::info!("📦 Payload Trace (Outbound to Gateway): {}", envelope);
                                                if let Ok(json_env) = serde_json::from_str::<serde_json::Value>(&envelope) {
                                                    if json_env.is_object() {
                                                        tracing::info!("✅ Payload is valid JSON object (DIDComm v2 structure check passed)");
                                                    } else {
                                                        tracing::warn!("⚠️ Payload is NOT a JSON object - valid DIDComm v2 messages should be JWE/JWS JSON objects.");
                                                    }
                                                } else {
                                                    tracing::warn!("⚠️ Payload is NOT valid JSON - valid DIDComm v2 messages should be JWE/JWS JSON.");
                                                }
                                                // -----------------------
                                                
                                                match client.post(uri).header("X-Routing-Token", token.clone()).body(envelope.clone()).send().await {
                                                    Ok(res) if res.status().is_success() => {
                                                        distributed_success = true;
                                                        tracing::info!("📤 Sent via JIT Gateway Routing");
                                                    },
                                                    Ok(res) => tracing::error!("❌ JIT Gateway Post failed: {}", res.status()),
                                                    Err(e) => tracing::error!("❌ JIT Gateway Post error: {}", e),
                                                }
                                            },
                                            _ => tracing::error!("❌ Failed to encrypt JIT token locally"),
                                        }
                                    } else {
                                        tracing::error!("❌ Gateway DID Doc found but missing routingKey");
                                    }
                                } else {
                                    tracing::error!("❌ Could not resolve Gateway DID: {}", routing_did);
                                }
                            } else {
                                tracing::error!("❌ Incomplete JIT serviceEndpoint object");
                            }
                        }
                    } else {
                        tracing::warn!("⚠️ No MessagingService found in DID Doc or serviceEndpoint is missing/invalid");
                    }
                }
            }
            
            // Fallback
            if !distributed_success {
                if let Some(store) = kv_stores.get("did_ledger") {
                    let encoded_key = hex::encode(&recipient);
                    if let Ok(Some(entry)) = store.get(encoded_key).await {
                        if let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&entry) {
                            if let Some(endpoint) = doc["service"].as_array()
                                .and_then(|services| services.iter().find(|s| s["type"] == "MessagingService"))
                                .and_then(|service| service["serviceEndpoint"].as_str()) {
                                
                                if endpoint.starts_with("nats://") {
                                    let subject = endpoint.split('/').last().unwrap_or(endpoint);
                                    if let Some(nc) = &shared.nats {
                                        if nc.publish(subject.to_string(), envelope.clone().into()).await.is_ok() {
                                            distributed_success = true;
                                            tracing::info!("📤 Sent via did_ledger endpoint: {}", subject);
                                        }
                                    }
                                } else {
                                    let client = reqwest::Client::new();
                                    if let Ok(res) = client.post(endpoint).body(envelope.clone()).send().await {
                                        if res.status().is_success() { distributed_success = true; }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            }
        }
    }

    if distributed_success {
        if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
            if let Ok(val) = serde_json::to_vec(&dto) {
                let _ = kv.put(msg_id.clone(), val.into()).await;
            }
        }
        Ok(serde_json::json!(msg_id))
    } else {
        tracing::error!("❌ Message distribution failed. Not persisting to outbox.");
        Err("Message distribution failed".to_string())
    }
}

pub async fn process_get_messages_logic(
    shared: Arc<WebauthnSharedState>,
    user_id: String,
    filter_did: Option<String>,
) -> Result<Vec<PlainDidcommDto>, String> {
    // 1. Get all user DIDs and their aliases for enrichment
    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id.clone(), tx)).await;
    let my_dids = rx.await.unwrap_or_default();
    
    let kv_meta = shared.kv_stores.as_ref().and_then(|m| m.get("user_identity_metadata"));
    let mut my_aliases = HashMap::new();
    for did in &my_dids {
        if let Some(kv) = kv_meta {
            let safe_did = did.replace(":", "_");
            let key = format!("{}.{}", user_id, safe_did);
            if let Ok(Some(entry)) = kv.get(&key).await {
                if let Ok(meta) = serde_json::from_slice::<crate::dto::UserIdentityMetadata>(&entry) {
                    if !meta.alias.is_empty() {
                        my_aliases.insert(did.clone(), meta.alias);
                    }
                }
            }
        }
    }

    // 2. Get the target DID (default to active DID)
    let target_did = match filter_did {
        Some(did) => {
            if !my_dids.contains(&did) {
                return Err("Unauthorized: You do not own this DID".to_string());
            }
            did
        },
        None => {
            resolve_active_did_for_user(shared.clone(), &user_id).await.map_err(|_| "Active DID not found".to_string())?
        }
    };

    let mut messages = Vec::new();
    
    if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
        if let Ok(mut keys) = kv.keys().await {
            while let Some(key_res) = keys.next().await {
                if let Ok(key) = key_res {
                    if let Ok(Some(entry)) = kv.get(key).await {
                        if let Ok(mut payload) = serde_json::from_slice::<PlainDidcommDto>(&entry) {
                            // Filter: Target DID must be sender OR one of the recipients
                            let is_recipient = payload.to.as_ref().map(|to| {
                                to.contains(&target_did)
                            }).unwrap_or(false);
                            
                            let is_sender = payload.from.as_ref() == Some(&target_did);

                            if is_recipient || is_sender {
                                // Enrichment: If it's a message to self or from me, attach alias
                                if let Some(from) = &payload.from {
                                    if let Some(alias) = my_aliases.get(from) {
                                        payload.alias = Some(alias.clone());
                                    }
                                }
                                
                                // Specific for self-service: if it's sent to me and I own the 'to' did
                                if payload.alias.is_none() {
                                    if let Some(to_vec) = &payload.to {
                                        for t in to_vec {
                                            if let Some(alias) = my_aliases.get(t) {
                                                payload.alias = Some(alias.clone());
                                                break;
                                            }
                                        }
                                    }
                                }

                                messages.push(payload);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Sort by created_time if available
    messages.sort_by_key(|m| m.created_time.unwrap_or(0));
    
    Ok(messages)
}

pub async fn process_accept_invitation_logic(
    shared: Arc<WebauthnSharedState>,
    user_id: String,
    invitation: OobInvitation,
) -> Result<serde_json::Value, String> {
    let my_did = resolve_active_did_for_user(shared.clone(), &user_id).await.map_err(|_| "DID not found".to_string())?;
    let target_did = invitation.from.clone();
    let invitation_id = invitation.id.clone();
    
    tracing::info!("🤝 [LOGIC] Accepting invitation from {} to {}", my_did, target_did);
    
    // Step 1: Add the inviter (target_did) to MY ACL
    let policy = crate::sovereign::gateway::common_types::ConnectionPolicy {
        did: target_did.clone(),
        alias: format!("Contact {}", &target_did[..12.min(target_did.len())]),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        permissions: vec![
            crate::sovereign::gateway::common_types::Permission::Chat,
            crate::sovereign::gateway::common_types::Permission::Discovery,
        ],
        status: crate::sovereign::gateway::common_types::ConnectionStatus::Active,
    };
    
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    shared.acl_cmd_tx.send(AclCommand::UpdatePolicy {
        owner: my_did.clone(), // Use DID as owner
        policy,
        resp: resp_tx,
    }).await.map_err(|e| format!("ACL send error: {}", e))?;
    
    let result = resp_rx.await.map_err(|e| format!("ACL recv error: {}", e))?;
    if let Err(e) = &result {
        return Err(format!("ACL update failed: {}", e));
    }
    tracing::info!("✅ [ACL] Connection Policy Updated for {} (Identity: {})", target_did, my_did);
    
    // Step 2: Send "invitation_accepted" message back to inviter
    let _accept_msg = format!("requesting acceptance for invitation {}", invitation_id);
    // Actually we need to send typed message. process_send_message_logic accepts generic body.
    // The "invitation_accepted" message type is handled by process_send_message logic via manual construction?
    // No, process_send_message_logic wraps in PlainDidcomm.
    // In main.rs, process_accept_invitation_logic manually constructed the message with "https://didcomm.org/invitation/1.0/accepted" type.
    // We should replicate that here, OR reuse process_send_message_logic if it supports custom types.
    // Yes it does support 'typ'.
    
    // Actually, process_accept_invitation_logic in main.rs (line 4160) constructs body: {"accepter_did": "..."}
    let body = format!("{{\"accepter_did\":\"{}\"}}", my_did);
    return process_send_message_logic(shared, user_id, None, target_did, body, "https://didcomm.org/invitation/1.0/accepted".to_string(), Some(invitation_id)).await;
}

// --- Handlers ---

pub async fn send_message_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    match process_send_message_logic(shared, claims.user_id, payload.from, payload.to.trim().to_string(), payload.body, payload.r#type, payload.thid).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            tracing::error!("❌ Send message error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_messages_handler(
    State(shared): State<Arc<WebauthnSharedState>>, 
    headers: HeaderMap,
    Query(query): Query<GetMessagesQuery>,
) -> Result<Json<Vec<PlainDidcommDto>>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let filter = query.recipient.filter(|r| !r.is_empty());
    match process_get_messages_logic(shared, claims.user_id, filter).await {
        Ok(msgs) => Ok(Json(msgs)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn accept_invitation_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(req): Json<HandshakeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let mut invitation = req.invitation;
    invitation.from = invitation.from.trim().to_string();
    match process_accept_invitation_logic(shared, claims.user_id, invitation).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            tracing::error!("❌ Accept invitation error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Additional handlers like create_identity, list_identities etc should also be here or in auth.rs.
// Given auth.rs is for "Authentication", "Identity" handlers might belong there or here.
// But `create_identity_handler` is used in registration flow logic? No, registration flow calls logic.
// Handlers are for API.
// `create_identity` is `vault` related.
// Let's put remaining handlers here.

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
    
    // Subscribe to DIDComm for the new DID
    if !did.is_empty() {
        tracing::info!("🆕 Created new DID: {}", did);
        
        // --- AUTO-STORE IN CONTACT STORE ---
        if let Ok(did_doc_json) = build_complete_did_document(shared.clone(), &did).await {
            // Map JSON to Rust type for ContactStoreCommand
            if let Ok(did_doc) = serde_json::from_value::<crate::sovereign::gateway::common_types::DidDocument>(did_doc_json) {
                let (cs_tx, cs_rx) = oneshot::channel();
                let _ = shared.contact_cmd_tx.send(ContactStoreCommand::StoreContact {
                    did_doc,
                    resp: cs_tx,
                }).await;
                
                if let Ok(Ok(_)) = cs_rx.await {
                    tracing::info!("📇 Auto-stored new identity {} in local contact_store", did);
                } else {
                    tracing::warn!("⚠️ Failed to auto-store new identity {} in contact_store", did);
                }
            } else {
                tracing::warn!("⚠️ Failed to deserialize newly built DID Document for {}", did);
            }
        }
        
        // Note: O(1) Wildcard Subscription automatically covers this new specific DID target.
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
    let _claims = extract_claims(&shared, &headers).await?;
    
    if let Some(nc) = &shared.nats {
        let js = async_nats::jetstream::new(nc.clone());
        let tenant_prefix = if shared.config.tenant_id.is_empty() {
            String::new()
        } else {
            format!("tenant_{}_", shared.config.tenant_id)
        };
        let stream_name = format!("{}agent_audit_stream", tenant_prefix);
        
        let stream = match js.get_stream(&stream_name).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Audit stream not found: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        
        let limit = params.limit.unwrap_or(300);
        
        let consumer = match stream.create_consumer(async_nats::jetstream::consumer::pull::Config {
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
            ..Default::default()
        }).await {
            Ok(c) => c,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        
        // ADDED .expires(...) to prevent the stream reader from hanging forever waiting for exactly `limit` events!
        let mut messages = match consumer.fetch().max_messages(limit).expires(std::time::Duration::from_millis(300)).messages().await {
            Ok(m) => m,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        
        let mut events = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_millis(50), messages.next()).await {
                Ok(Some(Ok(m))) => {
                    if let Ok(event) = serde_json::from_slice::<serde_json::Value>(&m.payload) {
                        events.push(event);
                    }
                    let _ = m.ack().await;
                }
                _ => {
                    // Break on timeout, stream completion, or error
                    break;
                }
            }
        }
        
        Ok(Json(serde_json::json!({
            "tenant_id": shared.config.tenant_id.clone(),
            "events": events,
            "total": events.len(),
            "has_more": false
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
                let key = format!("{}.{}", user_id, safe_did);
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
                 let _ = pub_store.put(user_id.clone(), serde_json::to_vec(&current_dids).unwrap().into()).await;
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
    
    let client = reqwest::Client::new();
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
    if (active_did.starts_with("did:twin:z") || active_did.starts_with("did:peer:z")) && active_did.len() >= 74 {
        let hex_part = &active_did[10..74];
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
        let client = reqwest::Client::new();
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
                            // SECURITY: This writes directly to the local dht_discovery KV bucket (not via
                            // the Gateway's HTTP POST /publish endpoint), so it is exempt from JWS
                            // signature verification. The Gateway's own public key is already known.
                            if let Some(kv_stores) = &shared.kv_stores {
                                if let Some(dht_store) = kv_stores.get("dht_discovery") {
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
                                    
                                    let blind_id = generate_blind_pointer(gw_did);
                                    if let Err(e) = publish_to_dht(dht_store, &blind_id, &gateway_doc).await {
                                        tracing::warn!("⚠️ Failed to self-heal Gateway DHT entry: {}", e);
                                    } else {
                                        tracing::info!("✅ Self-healed Gateway DHT entry for {}", gw_did);
                                    }
                                }
                            }
                            
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
            let safe_did = req.did.trim().replace(":", "_");
            let key = format!("{}.{}", user_id, safe_did);
            let meta = crate::dto::UserIdentityMetadata { 
                alias: req.alias.clone(),
                is_institutional: req.is_institutional.unwrap_or(false),
            };
            if let Ok(val) = serde_json::to_vec(&meta) {
                 let _ = store.put(key, val.into()).await;
                 return Ok(Json(serde_json::json!({ "status": "success" })));
            }
        }
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
    let policies = rx.await.unwrap_or_default();
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
    // We can use resolve_active_did_for_user which checks Vault via loop OR checks global cache if any.
    // resolve_active_did_for_user in auth.rs uses VaultCommand::GetActiveDid internally (Step 20: auth.rs line 21 calls Vault command).
    // Wait, let's Verify resolve_active_did_for_user implementation.
    // Reuse logic if it sends command.
    
    // Direct command sending:
    let (tx, rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(claims.user_id, tx)).await;
    let did = rx.await.unwrap_or_default();
    Ok(Json(serde_json::Value::String(did)))
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
    let _ = store.put(req_id, serde_json::to_vec(&request).unwrap().into()).await;
    
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
    let _ = store.put(req_id, serde_json::to_vec(&request).unwrap().into()).await;
    
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
    
    Ok(Json(serde_json::to_value(inv).unwrap()))
}

pub async fn register_gateway_did_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    Json(req): Json<RegisterGatewayRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Some(kv_stores) = &shared.kv_stores {
        let store = kv_stores.get("dht_discovery").ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        
        // Add public key if provided, otherwise extract from did:twin:z
        let mut verification_methods = vec![];
        if let Some(pub_key) = req.public_key {
            verification_methods.push(serde_json::json!({
                "id": format!("{}#routing-key", req.did),
                "type": "X25519KeyAgreementKey2019",
                "controller": req.did,
                "publicKeyBase64": pub_key
            }));
        } else if req.did.starts_with("did:twin:z") && req.did.len() >= 74 {
            let hex_part = &req.did[10..74];
            if let Ok(pub_bytes) = hex::decode(hex_part) {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);
                verification_methods.push(serde_json::json!({
                    "id": format!("{}#key-1", req.did),
                    "type": "Ed25519VerificationKey2018",
                    "controller": req.did,
                    "publicKeyBase64": b64
                }));
            }
        }
        
        let mut services = vec![];
        if let Some(endpoint) = req.endpoint {
            services.push(serde_json::json!({
                "id": format!("{}#messaging", req.did),
                "type": "MessagingService",
                "serviceEndpoint": endpoint
            }));
        }
        
        let did_doc = serde_json::json!({
            "id": req.did,
            "verificationMethod": verification_methods,
            "authentication": [],
            "service": services
        });

        // Publish to DHT (using blind pointer)
        let blind_id = generate_blind_pointer(&req.did);
        if let Err(e) = publish_to_dht(store, &blind_id, &did_doc).await {
            tracing::error!("❌ Failed to publish Gateway/External DID to DHT: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        tracing::info!("✅ Registered External/Gateway DID: {} (Blind: {})", req.did, blind_id);
        
        // Also pin to ledger if possible for O(n) scan fallback? 
        // For now, DHT is enough as resolution primary.

        return Ok(Json(serde_json::json!({"status": "registered", "did": req.did})));
    }
    Err(StatusCode::INTERNAL_SERVER_ERROR)
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

    // If we have NATS, we publish to the subject so the subscriber loops pick it up
    if let Some(nc) = &shared.nats {
        // The subject provided in URL is just the suffix (the hash). We need to reconstruct the full subject?
        // Wait, the logic.rs/publish_to_dht used: format!("{}/messaging/{}", base_url, subject)
        // And subscribe_to_did_didcomm subscribes to: format!("v1.didcomm.{}", compute_local_subject(...))
        // The `subject` in the URL *is* the `compute_local_subject` result.
        // Match the O(1) Wildcard Subscription subject format: v1.{node_id}.didcomm.{subject}
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

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("escalation_requests") {
            if let Ok(mut keys) = store.keys().await {
                while let Some(Ok(key)) = keys.next().await {
                    if let Ok(Some(entry)) = store.get(&key).await {
                        if let Ok(req) = serde_json::from_slice::<EscalationRequest>(&entry) {
                            // Primary filter: match owner_user_id against the authenticated user
                            let belongs_to_user = match &req.owner_user_id {
                                Some(uid) => uid == &claims.user_id,
                                // Fallback for legacy data without owner_user_id: match by DID
                                None => my_dids.contains(&req.user_did),
                            };
                            if belongs_to_user {
                                requests.push(req);
                            }
                        }
                    }
                }
            }
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

    let entry = store.get(&req_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut request: EscalationRequest = serde_json::from_slice(&entry)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // SECURITY: Verify the authenticated user owns this escalation request
    if let Some(ref owner_uid) = request.owner_user_id {
        if owner_uid != &claims.user_id {
            tracing::warn!("🔒 Unauthorized escalation approval: user {} tried to approve request owned by {}", claims.user_id, owner_uid);
            return Err(StatusCode::FORBIDDEN);
        }
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

    let effective_user_did = if request.user_did.is_empty() || request.user_did == "todo_verify_in_layer_above" {
        approving_did
    } else {
        request.user_did.clone()
    };

    let (tx_jwt, rx_jwt) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::IssueSessionJwt {
        subject: effective_user_did.clone(),
        scope,
        user_did: effective_user_did,
        ttl_seconds: elevated_ttl,
        tenant_id,
        resp: tx_jwt,
    }).await;

    let elevated_jwt = match rx_jwt.await {
        Ok(Ok(token)) => Some(token),
        Ok(Err(e)) => {
            tracing::warn!("⚠️ Failed to mint elevated JWT (connector tools may not need it): {}", e);
            None
        }
        Err(e) => {
            tracing::warn!("⚠️ Vault command channel failed: {}", e);
            None
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
            serde_json::to_string(&reply_payload).unwrap().into(),
        ).await {
            tracing::error!("❌ Failed to publish escalation approval via NATS: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        tracing::info!("✅ Published escalation approval for tool '{}' to {}", request.tool_name, request.nats_reply_subject);
    }

    // Update status
    request.status = "APPROVED".to_string();
    let _ = store.put(req_id, serde_json::to_vec(&request).unwrap().into()).await;

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

    let entry = store.get(&req_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut request: EscalationRequest = serde_json::from_slice(&entry)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // SECURITY: Verify the authenticated user owns this escalation request
    if let Some(ref owner_uid) = request.owner_user_id {
        if owner_uid != &claims.user_id {
            tracing::warn!("🔒 Unauthorized escalation denial: user {} tried to deny request owned by {}", claims.user_id, owner_uid);
            return Err(StatusCode::FORBIDDEN);
        }
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
            serde_json::to_string(&reply_payload).unwrap().into(),
        ).await {
            tracing::error!("❌ Failed to publish escalation denial via NATS: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        tracing::info!("🚫 Published escalation denial for tool '{}' to {}", request.tool_name, request.nats_reply_subject);
    }

    // Update status
    request.status = "DENIED".to_string();
    let _ = store.put(req_id, serde_json::to_vec(&request).unwrap().into()).await;

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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // 1. Fetch MCP tools from connector_mcp_server
    let connector_url = &shared.config.connector_mcp_url;
    let mcp_tools = match client.get(format!("{}/tools/list", connector_url)).send().await {
        Ok(res) if res.status().is_success() => {
            res.json::<serde_json::Value>().await.unwrap_or(serde_json::json!([]))
        }
        _ => serde_json::json!([]),
    };

    // 2. Fetch Claw skills from native_skill_executor
    let executor_url = &shared.config.skill_executor_url;
    let claw_skills = match client.get(format!("{}/skills", executor_url)).send().await {
        Ok(res) if res.status().is_success() => {
            res.json::<serde_json::Value>().await.unwrap_or(serde_json::json!([]))
        }
        _ => serde_json::json!([]),
    };

    // 3. Build unified registry
    let mcp_count = mcp_tools.as_array().map(|a| a.len()).unwrap_or(0);
    let claw_count = claw_skills.as_array().map(|a| a.len()).unwrap_or(0);

    tracing::info!("📋 Skill registry: {} MCP tools, {} Claw skills", mcp_count, claw_count);

    Json(serde_json::json!({
        "version": "1.0",
        "host_id": shared.config.tenant_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "mcp_tools": mcp_tools,
        "claw_skills": claw_skills,
        "total_skills": mcp_count + claw_count,
    }))
}

// --- Restaurant Proxy Handlers ---
// These handlers let the customer_ordering_portal interact with the restaurant_state_service
// through an authenticated channel, with the Host injecting the real customer DID.

fn restaurant_service_url(shared: &Arc<crate::shared_state::WebauthnSharedState>) -> String {
    shared.config.restaurant_service_url.clone()
}

/// Proxy restaurant tool invocations through the Host backend.
/// The customer portal sends authenticated requests here, and the Host
/// forwards them to the restaurant_state_service after JWT validation.
/// The customer_did is injected server-side from the JWT to prevent spoofing.
pub async fn restaurant_invoke_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // 1. Extract and validate JWT
    let claims = match extract_claims(&shared, &headers).await {
        Ok(c) => c,
        Err(status) => return status.into_response(),
    };

    // 2. Resolve the user's active DID
    let active_did = match resolve_active_did_for_user(shared.clone(), &claims.user_id).await {
        Ok(did) => did,
        Err(_) => {
            // If no active DID yet, use a derived identifier from user_id
            format!("did:local:{}", claims.user_id)
        }
    };

    // 3. Parse the incoming request and inject the real DID
    let mut req_json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Inject authenticated customer_did into arguments
    if let Some(args) = req_json.get_mut("arguments") {
        if let Some(obj) = args.as_object_mut() {
            obj.insert("customer_did".to_string(), serde_json::json!(active_did));
        }
    } else {
        req_json["arguments"] = serde_json::json!({ "customer_did": active_did });
    }

    // Ensure action_id exists
    if req_json.get("action_id").is_none() {
        req_json["action_id"] = serde_json::json!(format!("proxy_{}", uuid::Uuid::new_v4()));
    }
    // Ensure tenant_id exists
    if req_json.get("tenant_id").is_none() {
        let tenant = shared.config.restaurant_tenant_id.clone()
            .unwrap_or_else(|| "rest_demo".to_string());
        req_json["tenant_id"] = serde_json::json!(tenant);
    }

    tracing::info!("🍽️ Restaurant proxy: user={}, did={}, skill={}", 
        claims.username, active_did,
        req_json.get("skill_name").and_then(|s| s.as_str()).unwrap_or("?"));

    // 4. Forward to restaurant_state_service
    let client = reqwest::Client::new();
    match client
        .post(format!("{}/invoke", restaurant_service_url(&shared)))
        .header("Content-Type", "application/json")
        .json(&req_json)
        .send()
        .await
    {
        Ok(resp) => {
            let status_code = resp.status();
            let resp_body = resp.text().await.unwrap_or_default();
            (
                StatusCode::from_u16(status_code.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                resp_body,
            ).into_response()
        }
        Err(e) => {
            tracing::error!("❌ Restaurant proxy error: {}", e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Public menu endpoint — reads menu from restaurant_state_service.
/// No JWT required (menu is public), but still proxied through Host
/// to keep the restaurant_state_service unexposed to the browser.
pub async fn restaurant_menu_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
) -> impl IntoResponse {
    let tenant = shared.config.restaurant_tenant_id.clone()
        .unwrap_or_else(|| "rest_demo".to_string());

    let req_json = serde_json::json!({
        "action_id": format!("menu_{}", uuid::Uuid::new_v4()),
        "skill_name": "restaurant_menu_read",
        "arguments": {},
        "tenant_id": tenant
    });

    let client = reqwest::Client::new();
    match client
        .post(format!("{}/invoke", restaurant_service_url(&shared)))
        .header("Content-Type", "application/json")
        .json(&req_json)
        .send()
        .await
    {
        Ok(resp) => {
            let resp_body = resp.text().await.unwrap_or_default();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                resp_body,
            ).into_response()
        }
        Err(e) => {
            tracing::error!("❌ Restaurant menu proxy error: {}", e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
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
    // Set the new peer identity as the active DID immediately for a smoother UI experience
    let (act_tx, act_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::SetActiveDid(user_id.clone(), peer_did.clone(), act_tx)).await;
    let _ = act_rx.await;

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
        let _ = kv.put(req_id, serde_json::to_vec(&pending_req).unwrap().into()).await;
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
