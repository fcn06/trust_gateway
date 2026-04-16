use std::sync::Arc;
use tokio::sync::oneshot;
use futures::StreamExt;

use crate::shared_state::WebauthnSharedState;
use crate::commands::VaultCommand;
use crate::dto::{IncomingMessage, PlainDidcommDto, map_dto_to_wit};
use crate::handlers::api::handle_incoming_message_bypass_logic;

// === JIT Routing / O(1) Subscription Logic ===

/// Populates the target_id -> DID map on startup by iterating all users and their DIDs.
pub async fn populate_target_id_map(shared: Arc<WebauthnSharedState>) {
    tracing::info!("🔄 Populating Target ID Map from persistence...");
    
    let Some(kv_stores) = &shared.kv_stores else {
        tracing::warn!("⚠️ KV Stores not available, cannot populate target map.");
        return;
    };

    // 1. Get all User IDs
    // We iterate 'username_to_userid' to find users.
    let mut user_ids = Vec::new();
    if let Some(user_store) = kv_stores.get("username_to_userid") {
        if let Ok(mut keys) = user_store.keys().await {
            while let Some(Ok(key)) = keys.next().await {
                 if let Ok(Some(uid_bytes)) = user_store.get(&key).await {
                     if let Ok(uid) = String::from_utf8(uid_bytes.into()) {
                         user_ids.push(uid);
                     }
                 }
            }
        }
    }

    // 2. For each user, get DIDs -> Compute Target ID -> Insert to Map
    let mut count = 0;
    // We need to access blind data. We can't decrypt it easily without Vault logic.
    // BUT, we don't need to decrypt the DIDs if we can't.
    // Wait, 'user_dids:{userid}' is blind encrypted. Host cannot read it without Vault.
    // This is a problem. Host cannot populate map without Vault help.
    
    // SOLUTION: Use Vault to list identities?
    // We cannot call Vault Wasm here easily without an instance.
    // But we are in `loops.rs` where we spawn Vault loop.
    // We can send `VaultCommand::ListIdentities` for each user.
    // BUT `ListIdentities` requires a `resp` channel.
    
    // We will spawn a task to do this via Vault Loop.
    for user_id in user_ids {
        let (tx, rx) = oneshot::channel();
        if shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id.clone(), tx)).await.is_ok() {
            if let Ok(dids) = rx.await {
                let mut map = shared.target_id_map.lock().unwrap();
                for did in dids {
                    let target_id = crate::logic::compute_local_subject(&did, &shared.house_salt);
                    map.insert(target_id, did);
                    count += 1;
                }
            }
        }
    }
    
    tracing::info!("✅ Target ID Map populated with {} entries.", count);
}

pub fn subscribe_to_node_wildcard(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot subscribe to Node Wildcard: NATS not available");
        return;
    };
    
    let node_id = crate::logic::compute_node_id(&shared.house_salt);
    let subject = if shared.config.tenant_id.is_empty() {
        format!("v1.{}.>", node_id)
    } else {
        format!("v1.{}.{}.>", shared.config.tenant_id, node_id)
    };
    let queue_group = "host_orchestrator"; // Optional: Load balance if we had multiple hosts
    
    let shared_clone = shared.clone();
    
    tokio::spawn(async move {
        tracing::info!("🌐 [O(1)] Subscribing to Node Wildcard: {}", subject);
        
        // Deduplication Cache: (Payload Hash, Timestamp)
        // We use a simple u64 hash for speed. Collisions are unlikely for distinct messages in 5s window.
        use std::collections::VecDeque;
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        use std::time::{Instant, Duration};

        let mut recent_msgs: VecDeque<(u64, Instant)> = VecDeque::with_capacity(100);
        const DEDUPE_WINDOW: Duration = Duration::from_secs(5);

        // Use queue group to robustness, though we are single node.
        if let Ok(mut sub) = nats.queue_subscribe(subject.clone(), queue_group.to_string()).await {
             while let Some(msg) = sub.next().await {
                // 1. Deduplication Check
                let mut hasher = DefaultHasher::new();
                msg.payload.hash(&mut hasher);
                msg.subject.hash(&mut hasher); // Fix: Include subject to distinguish different requests with same payload
                let p_hash = hasher.finish();
                let now = Instant::now();

                // Prune expired
                while let Some((_, ts)) = recent_msgs.front() {
                    if now.duration_since(*ts) > DEDUPE_WINDOW {
                        recent_msgs.pop_front();
                    } else {
                        break;
                    }
                }

                // Check for duplicates
                let is_duplicate = recent_msgs.iter().any(|(h, _)| *h == p_hash);
                if is_duplicate {
                    tracing::debug!("♻️ Duplicate message suppressed (Hash: {:x})", p_hash);
                    continue;
                }
                
                recent_msgs.push_back((p_hash, now));

                // Parse Subject: v1.{node_id}.{category}.{target_id}
                // e.g. v1.NODE.didcomm.TARGET
                let subject_str = msg.subject.to_string();
                let parts: Vec<&str> = subject_str.split('.').collect();
                if parts.len() < 4 {
                    tracing::warn!("⚠️ Received malformed subject: {}", subject_str);
                    continue;
                }
                
                let category = parts[2];
                let target_id = parts[3];
                
                // 2. Dispatch based on category
                match category {
                    "didcomm" => {
                        // Resolve DID from Target ID (JIT Routing)
                        let did_opt = {
                            let map = shared_clone.target_id_map.lock().unwrap();
                            map.get(target_id).cloned()
                        };
                        
                        let did = match did_opt {
                            Some(d) => d,
                            None => {
                                tracing::debug!("⚠️ Unknown target_id: {} on subject {}", target_id, subject_str);
                                continue;
                            }
                        };

                        let envelope = String::from_utf8_lossy(&msg.payload).to_string();
                        
                        // In the hybrid architecture, messages arrive as plaintext JSON from the gateway.
                        // MLS encryption/decryption is handled at the component level.
                        // We parse the envelope directly as a PlainDidcommDto.
                        let payload_res = serde_json::from_str::<PlainDidcommDto>(&envelope);
                        
                        if let Ok(payload) = payload_res {
                             let final_envelope = Some(envelope);
                             let didcomm_msg = map_dto_to_wit(payload);
                             if handle_incoming_message_bypass_logic(&shared_clone, &did, &didcomm_msg, &final_envelope).await {
                                 continue;
                             }
                             let _ = shared_clone.messaging_cmd_tx.send(IncomingMessage { 
                                 msg: didcomm_msg, 
                                 envelope: final_envelope 
                             }).await;
                        }
                    },
                    "auth" | "inbox" | "outbound" | "acl" | "identity" | "mcp" | "invitations" => {
                        // Portal requests use parts[3] as Account ID (AID), not Target ID
                        let aid = target_id;
                        let action = parts.get(4).cloned().unwrap_or_default();
                        
                        // Pass to portal dispatcher
                        crate::auth::handle_portal_request(
                            shared_clone.clone(),
                            category,
                            aid,
                            action,
                            msg.payload.to_vec(),
                            msg.reply.as_ref().map(|s| s.to_string())
                        ).await;
                    },
                    "wallet" => {
                        // Wallet-bound messages from connected pairwise DIDs
                        // These arrive when a wallet connection sends a message through the gateway
                        let did_opt = {
                            let map = shared_clone.target_id_map.lock().unwrap();
                            map.get(target_id).cloned()
                        };
                        
                        let did = match did_opt {
                            Some(d) => d,
                            None => {
                                tracing::debug!("⚠️ Unknown wallet target_id: {} on subject {}", target_id, subject_str);
                                continue;
                            }
                        };

                        tracing::info!("📲 Wallet message received for pairwise DID: {}", did);
                        
                        let envelope = String::from_utf8_lossy(&msg.payload).to_string();
                        
                        // Parse as DIDComm and route through messaging pipeline
                        if let Ok(payload) = serde_json::from_str::<PlainDidcommDto>(&envelope) {
                            let didcomm_msg = map_dto_to_wit(payload);
                            let _ = shared_clone.messaging_cmd_tx.send(IncomingMessage { 
                                msg: didcomm_msg, 
                                envelope: Some(envelope)
                            }).await;
                        } else {
                            tracing::warn!("⚠️ Failed to parse wallet message as DIDComm");
                        }
                    },
                    _ => {
                        tracing::warn!("⚠️ Unhandled category: {} on subject {}", category, subject_str);
                    }
                }
             }
        } else {
            tracing::error!("❌ Failed to subscribe to Node Wildcard: {}", subject);
        }
    });
}
