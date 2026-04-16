use std::sync::Arc;
use wasmtime::{Engine, component::{Component, Linker}};
use tokio::sync::mpsc::Receiver;

use crate::shared_state::{HostState, WebauthnSharedState};
use crate::dto::IncomingMessage;
use crate::bindings::messaging_bindgen;
use crate::dto::{PlainDidcommDto, map_wit_to_dto, map_dto_to_wit};
use super::create_store;
use super::routing::{populate_target_id_map, subscribe_to_node_wildcard};

// 4. Messaging Loop Task
pub fn spawn_messaging_loop(
    engine: Engine,
    shared: Arc<WebauthnSharedState>,
    messaging_comp: Component,
    linker: Linker<HostState>,
    mut messaging_rx: Receiver<IncomingMessage>,
    profile: &str, // Pass "debug" or "release"
) {
    let profile = profile.to_string();
    
    // NEW: Populate Target ID Map and Subscribe to O(1) Wildcard
    let shared_for_setup = shared.clone();
    tokio::spawn(async move {
        populate_target_id_map(shared_for_setup.clone()).await;
        subscribe_to_node_wildcard(shared_for_setup);
    });

    tokio::spawn(async move {
        let mut store = create_store(&engine, shared);

        let inst = linker.instantiate_async(&mut store, &messaging_comp).await.expect("Messaging init failed");
        store.data_mut().messaging = Some(inst);
        
        while let Some(incoming) = messaging_rx.recv().await {
                let inst_opt = store.data().messaging.clone();
                if let Some(inst) = inst_opt {
                    if let Ok(client) = messaging_bindgen::MessagingService::new(&mut store, &inst) {
                        let handler = client.sovereign_gateway_messaging_handler();
                        let msg = incoming.msg;
                        let envelope = incoming.envelope;

                        // Convert MlsMessage to DTO for field access throughout this loop
                        let mut dto = map_wit_to_dto(&msg, envelope.clone());
                        let msg_id = dto.id.clone();
                        let msg_type = dto.r#type.clone();

                        match handler.call_handle_incoming(&mut store, &msg).await {
                            Ok(Ok(true)) => {
                                tracing::info!("✅ Message handled and authorized: {}", msg_id);
                                dto.status = Some("distributed".to_string());
                                // Store message in JetStream
                                match store.data().shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
                                    Some(kv) => {
                                         tracing::info!("📥 Message FROM: {:?}, TO: {:?}", dto.from, dto.to);
                                         let msg_bytes = serde_json::to_vec(&dto).unwrap();
                                         if let Ok(_) = kv.put(msg_id.clone(), msg_bytes.clone().into()).await {
                                             tracing::info!("💾 Persisted message {} (JetStream)", msg_id);
                                            
                                            // PUSH NOTIFICATION: If message has a thid, notify listeners via NATS
                                            if let Some(thid) = &dto.thid {
                                                if let Some(nc) = &store.data().shared.nats {
                                                    let subject = format!("handshake.{}.completed", thid);
                                                    let _ = nc.publish(subject.clone(), msg_bytes.into()).await;
                                                    tracing::info!("📢 Published handshake completion to NATS: {}", subject);
                                                }
                                            }

                                            // --- V5 INSTITUTIONAL AUTO-REPLY ---
                                            if msg_type == "https://didcomm.org/message/2.0/chat" {
                                                if let Some(recipients) = &dto.to {
                                                    if let Some(first_recipient) = recipients.first() {
                                                        let (tx, rx) = tokio::sync::oneshot::channel();
                                                        let _ = store.data().shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid {
                                                            did: first_recipient.clone(),
                                                            resp: tx
                                                        }).await;
                                                        
                                                        if let Ok(Some(user_id)) = rx.await {
                                                            if !user_id.is_empty() {
                                                                if let Some(meta_store) = store.data().shared.kv_stores.as_ref().and_then(|m| m.get("user_identity_metadata")) {
                                                                    let safe_did = first_recipient.trim().replace(":", "_");
                                                                    let key = format!("{}.{}", user_id, safe_did);
                                                                    if let Ok(Some(entry)) = meta_store.get(&key).await {
                                                                        if let Ok(meta) = serde_json::from_slice::<crate::dto::UserIdentityMetadata>(&entry) {
                                                                            if meta.is_institutional {
                                                                                tracing::info!("🤖 Institutional recipient detected! Dispatching to agent...");
                                                                                let shared_clone = store.data().shared.clone();
                                                                                let sender_clone = dto.from.clone().unwrap_or_default();
                                                                                let user_clone = user_id.clone();
                                                                                
                                                                                let body_str = dto.body.to_string();
                                                                                let mut text_msg = String::new();
                                                                                if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(&body_str) {
                                                                                    if let Some(content) = body_json.get("content").and_then(|c| c.as_str()) {
                                                                                        text_msg = content.to_string();
                                                                                    }
                                                                                }
                                                                                if text_msg.is_empty() { text_msg = body_str; }
                                                                                let inst_did_clone = first_recipient.clone();
                                                                                let thid_clone = dto.thid.clone().or_else(|| Some(msg_id.clone()));
                                                                                 let thid_to_pass = thid_clone.clone();
                                                                                tokio::spawn(async move {
                                                                                     match crate::handlers::agent::dispatch_to_ssi_agent(
                                                                                         shared_clone.clone(),
                                                                                         &sender_clone,
                                                                                         &user_clone,
                                                                                         &text_msg,
                                                                                         true, // is_institutional is true if we reached this block
                                                                                         thid_to_pass,
                                                                                     ).await {
                                                                                         Ok(agent_text) => {
                                                                                             tracing::info!("📤 Routing Agent reply back to {}", sender_clone);
                                                                                             
                                                                                             // The agent might return a JSON string in its 'text' field (e.g. \"{\\\"body\\\": \\\"...\\\"}\" )
                                                                                             // OR a simple quoted string \"text\". We want the raw unquoted text.
                                                                                             let mut final_text = agent_text.to_string();
                                                                                             if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&agent_text) {
                                                                                                 if let Some(b) = json_val.get("body").and_then(|v| v.as_str()) {
                                                                                                     final_text = b.to_string();
                                                                                                 } else if let Some(s) = json_val.as_str() {
                                                                                                     final_text = s.to_string();
                                                                                                 }
                                                                                             } else if final_text.starts_with('"') && final_text.ends_with('"') {
                                                                                                // Manual unquote if it's a JSON string but from_str failed for some reason
                                                                                                final_text = final_text[1..final_text.len()-1].replace("\\\"", "\"").replace("\\n", "\n");
                                                                                             }
                                                                                             
                                                                                             let body_json = serde_json::json!({ "content": final_text });
                                                                                             let _ = crate::handlers::api::process_send_message_logic(
                                                                                                 shared_clone,
                                                                                                 user_clone,
                                                                                                 Some(inst_did_clone),
                                                                                                 sender_clone,
                                                                                                 body_json.to_string(),
                                                                                                 "https://didcomm.org/message/2.0/chat".to_string(),
                                                                                                 thid_clone
                                                                                             ).await;
                                                                                         }
                                                                                         Err((status, err_msg)) => {
                                                                                             tracing::error!("Agent dispatch failed ({}): {}", status, err_msg);
                                                                                         }
                                                                                     }
                                                                                 });
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            
                                            // --- V5 AGENT DISCOVERY DISCLOSE INTERCEPT ---
                                            // Intercept disclose messages to return them synchronously to the NATS bridge inline
                                            if msg_type == "https://didcomm.org/discover-features/2.0/disclose" {
                                                if let Some(thid) = &dto.thid {
                                                    if let Some(nc) = &store.data().shared.nats {
                                                        let subject = format!("mcp.v1.discovery.reply.{}", thid);
                                                        tracing::info!("📢 Intercepted discovery disclose, publishing to NATS: {}", &subject);
                                                        let payload = dto.body.to_string();
                                                        let _ = nc.publish(subject.clone(), payload.into()).await;
                                                        
                                                        // Prevent this from being shown as a normal chat message to the user
                                                        dto.status = Some("consumed_internally".to_string());
                                                        if let Some(kv) = store.data().shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
                                                            if let Ok(val) = serde_json::to_vec(&dto) {
                                                                let _ = kv.put(msg_id.clone(), val.into()).await;
                                                            }
                                                        }
                                                        continue; // skip the rest of message processing
                                                    }
                                                }
                                            }
                                            // --- V5 AGENT DISCOVERY INTERCEPT ---
                                            if msg_type == "https://didcomm.org/discover-features/2.0/queries" {
                                                if let Some(recipients) = &dto.to {
                                                    if let Some(first_recipient) = recipients.first() {
                                                        let sender_did = dto.from.clone().unwrap_or_default();
                                                        let our_did = first_recipient.clone();
                                                        let query_thid = dto.thid.clone().unwrap_or_else(|| msg_id.clone());
                                                        let shared_clone = store.data().shared.clone();

                                                        let (tx, rx) = tokio::sync::oneshot::channel();
                                                        let _ = store.data().shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid {
                                                            did: our_did.clone(),
                                                            resp: tx
                                                        }).await;
                                                        
                                                        if let Ok(Some(user_id)) = rx.await {
                                                            if !user_id.is_empty() {
                                                                tracing::info!("🔍 Discovery Query detected! Fetching MCP tools to reply...");
                                                                tokio::spawn(async move {
                                                                    // Fetch MCP tools from NATS bridge (real tools like weather, calendar, etc.)
                                                                    let mut tools_json = serde_json::json!([]);
                                                                    if let Some(nats) = shared_clone.nats.as_ref() {
                                                                        match tokio::time::timeout(
                                                                            std::time::Duration::from_secs(5),
                                                                            nats.request("mcp.v1.dispatch.list_tools".to_string(), "".into())
                                                                        ).await {
                                                                            Ok(Ok(reply)) => {
                                                                                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&reply.payload) {
                                                                                    // Extract tool names and descriptions
                                                                                    if let Some(tools) = parsed.get("tools").and_then(|t| t.as_array()) {
                                                                                        let simplified: Vec<serde_json::Value> = tools.iter().map(|t| {
                                                                                            serde_json::json!({
                                                                                                "name": t.get("name").and_then(|n| n.as_str()).unwrap_or("unknown"),
                                                                                                "description": t.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                                                                                            })
                                                                                        }).collect();
                                                                                        tools_json = serde_json::json!(simplified);
                                                                                        tracing::info!("✅ Got {} MCP tools from NATS bridge", simplified.len());
                                                                                    }
                                                                                }
                                                                            }
                                                                            Ok(Err(e)) => tracing::warn!("⚠️ NATS request for tools failed: {}", e),
                                                                            Err(_) => tracing::warn!("⚠️ NATS request for tools timed out"),
                                                                        }
                                                                    }

                                                                    // Also fetch A2A skills from HTTP /skills for completeness
                                                                    let client = reqwest::Client::new();
                                                                    let agent_url = shared_clone.config.ssi_agent_endpoint.clone();
                                                                    let mut a2a_skills = serde_json::json!([]);
                                                                    if let Ok(res) = client.get(&format!("{}/skills", agent_url)).send().await {
                                                                        if res.status().is_success() {
                                                                            if let Ok(skills) = res.json::<serde_json::Value>().await {
                                                                                a2a_skills = skills;
                                                                            }
                                                                        }
                                                                    }

                                                                    let body = serde_json::json!({
                                                                        "mcp_tools": tools_json,
                                                                        "a2a_skills": a2a_skills
                                                                    }).to_string();
                                                                    
                                                                    if let Err(e) = crate::handlers::api::process_send_message_logic(
                                                                        shared_clone,
                                                                        user_id,
                                                                        Some(our_did),
                                                                        sender_did,
                                                                        body,
                                                                        "https://didcomm.org/discover-features/2.0/disclose".to_string(),
                                                                        Some(query_thid.clone()) // Correlate
                                                                    ).await {
                                                                        tracing::error!("Failed to send discovery disclose: {}", e);
                                                                    } else {
                                                                        tracing::info!("✅ Sent discovery disclosure via DIDComm (thid: {:?})", query_thid);
                                                                    }
                                                                });
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // -----------------------------------
                                        }
                                    },
                                    None => tracing::warn!("⚠️ NATS KV not available, message {} NOT persisted", msg_id),
                                }
                            }
                            Ok(Ok(false)) => {
                                tracing::warn!("🛑 Message denied by handler");
                                dto.status = Some("rejected".to_string());
                                match store.data().shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
                                    Some(kv) => {
                                        if let Ok(val) = serde_json::to_vec(&dto) {
                                            let _ = kv.put(msg_id.clone(), val.into()).await;
                                            tracing::info!("💾 Persisted REJECTED message {} (JetStream)", msg_id);
                                        }
                                    },
                                    None => tracing::warn!("⚠️ NATS KV not available, message {} NOT persisted", msg_id),
                                }
                            }
                            Ok(Err(e)) => tracing::error!("❌ Message handler returned error: {}", e),
                            Err(e) => tracing::error!("❌ Wasm execution error: {:?}", e),
                        }
                    }
                }
        }
    });
}


// Beacon loop removed in hybrid pivot — beacons were used with DIDComm/recovery model.
// Inter-user messaging now uses OpenMLS via HTTP gateway.
