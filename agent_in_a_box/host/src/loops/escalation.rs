use std::sync::Arc;
use futures::StreamExt;

use crate::shared_state::WebauthnSharedState;

/// Spawn the MCP ActionRequest escalation loop.
///
/// This loop bridges the `vp_mcp_server` ↔ Wallet flow:
/// 1. Subscribes to `mcp.escalate.>` NATS requests from MCP Server.
/// 2. Encrypts the ActionRequest into a DIDComm JWE for the Wallet.
/// 3. Pushes it to the Gateway via NATS `gateway.push.<wallet_did>`.
/// 4. Waits for a signed ActionResponse from the Wallet on `mcp.escalate.replies`.
/// 5. Replies back to the MCP Server's original NATS request.
pub fn spawn_mcp_escalation_loop(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot start MCP escalation loop: NATS not available");
        return;
    };

    tracing::info!("🔗 MCP Escalation Loop: OID4VP mode (standard wallet flow)");

    let nats_reply = nats.clone();
    let nats_push = nats.clone();

    // Spawn a task that listens for ActionRequests from the MCP server
    tokio::spawn(async move {
        let subject = "mcp.escalate.>";
        tracing::info!("🔒 Subscribing to MCP escalation requests on: {}", subject);

        let mut sub = match nats.subscribe(subject.to_string()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to MCP escalation: {}", e);
                return;
            }
        };

        while let Some(msg) = sub.next().await {
            let payload_str = String::from_utf8_lossy(&msg.payload).to_string();
            tracing::info!("🔒 MCP ActionRequest received: {}…", &payload_str[..payload_str.len().min(120)]);

            // Parse the ActionRequest
            let action_req: ssi_crypto::ucan::ActionRequest = match serde_json::from_str(&payload_str) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("❌ Invalid ActionRequest: {}", e);
                    if let Some(reply) = msg.reply {
                        let _ = nats_reply.publish(reply.to_string(),
                            serde_json::to_vec(&serde_json::json!({"approved": false, "error": "parse_error"})).unwrap().into()
                        ).await;
                    }
                    continue;
                }
            };

            let request_id = action_req.request_id.clone();

            // ── OID4VP Flow: Store in KV for wallet retrieval ──
            // Instead of pushing via WSS, we store the ActionRequest in the
            // `pending_oid4vp_requests` KV bucket. The oid4vp.rs handler will
            // serve it as a signed JWT when the wallet fetches the request_uri.
            if let Some(kv) = shared.kv_stores.as_ref()
                .and_then(|m| m.get("pending_oid4vp_requests"))
            {
                let req_bytes = serde_json::to_vec(&action_req).unwrap();
                if let Err(e) = kv.put(request_id.clone(), req_bytes.into()).await {
                    tracing::error!("❌ Failed to store OID4VP request in KV: {}", e);
                }
            }

            // Compute node_id and gateway_url for the QR code URI
            let node_id = crate::logic::compute_node_id(&shared.house_salt);
            let gateway_url = shared.gateway_url.clone()
                .or_else(|| Some(shared.config.service_gateway_base_url.clone()))
                .unwrap_or_else(|| std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:3002".to_string()));

            // Notify the frontend so it can render an OID4VP QR code
            let qr_notification = serde_json::json!({
                "node_id": node_id,
                "request_id": request_id,
                "gateway_url": gateway_url,
                "tool_name": action_req.tool_name,
                "human_summary": action_req.human_summary,
                "qr_uri": format!(
                    "openid4vp://authorize?client_id={}&request_uri={}/oid4vp/request/{}/{}",
                    urlencoding::encode(&shared.oid4vp_client_id),
                    gateway_url.trim_end_matches('/'),
                    node_id,
                    request_id,
                ),
            });
            let _ = nats_push.publish(
                "host.v1.oid4vp.pending".to_string(),
                serde_json::to_vec(&qr_notification).unwrap().into(),
            ).await;
            tracing::info!("📤 OID4VP request stored and QR notification published for '{}'", request_id);

            // Now we need to wait for the ActionResponse from the wallet.
            // The Gateway forwards wallet action_responses to `mcp.escalate.replies`.
            // We subscribe to that and match by request_id.
            let reply_sub = match nats_reply.subscribe("mcp.escalate.replies".to_string()).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("❌ Failed to subscribe to escalation replies: {}", e);
                    continue;
                }
            };

            let timeout_result = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                wait_for_action_response(reply_sub, &request_id),
            ).await;

            match timeout_result {
                Ok(Some(response)) => {
                    tracing::info!("✅ Received ActionResponse for '{}': approved={}", request_id, response.approved);
                    if let Some(reply) = msg.reply {
                        let resp_bytes = serde_json::to_vec(&response).unwrap();
                        let _ = nats_reply.publish(reply.to_string(), resp_bytes.into()).await;
                    }
                }
                Ok(None) => {
                    tracing::warn!("⚠️ Reply stream closed without matching response for {}", request_id);
                    if let Some(reply) = msg.reply {
                        let _ = nats_reply.publish(reply.to_string(),
                            serde_json::to_vec(&serde_json::json!({"approved": false, "error": "no_response"})).unwrap().into()
                        ).await;
                    }
                }
                Err(_) => {
                    tracing::warn!("⏱️ Timeout waiting for ActionResponse for {}", request_id);
                    if let Some(reply) = msg.reply {
                        let _ = nats_reply.publish(reply.to_string(),
                            serde_json::to_vec(&serde_json::json!({"approved": false, "error": "timeout"})).unwrap().into()
                        ).await;
                    }
                }
            }
        }
    });
}

/// Wait for an ActionResponse that matches a specific request_id on the reply stream.
async fn wait_for_action_response(
    mut sub: async_nats::Subscriber,
    request_id: &str,
) -> Option<ssi_crypto::ucan::ActionResponse> {
    while let Some(msg) = sub.next().await {
        if let Ok(resp) = serde_json::from_slice::<ssi_crypto::ucan::ActionResponse>(&msg.payload) {
            if resp.request_id == request_id {
                return Some(resp);
            }
        }
    }
    None
}

/// NATS listener for escalation requests from the mcp_nats_bridge.
///
/// When an agent triggers a mutation tool with standard clearance,
/// the bridge publishes an escalation request to `host.v1.escalation.request`.
/// This listener stores the request in KV and waits for user approval via the portal UI.
pub fn subscribe_to_escalation_requests(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot subscribe to escalation requests: NATS not available");
        return;
    };

    tokio::spawn(async move {
        let subject = "host.v1.escalation.request";
        tracing::info!("🔒 Subscribing to escalation requests on: {}", subject);

        match nats.subscribe(subject.to_string()).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    let payload_str = String::from_utf8_lossy(&msg.payload).to_string();
                    tracing::info!("🔒 Received escalation request: {}", payload_str);

                    // Parse the escalation request from the bridge
                    let parsed: serde_json::Value = match serde_json::from_str(&payload_str) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!("❌ Failed to parse escalation request: {}", e);
                            continue;
                        }
                    };

                    let tool_name = parsed["tool_name"].as_str().unwrap_or("unknown").to_string();
                    let user_did = parsed["user_did"].as_str().unwrap_or("unknown").to_string();
                    let requester_did = parsed["requester_did"].as_str().unwrap_or("unknown").to_string();
                    let correlation_id = parsed["correlation_id"].as_str().unwrap_or("").to_string();
                    let arguments = parsed.get("original_arguments").cloned();

                    // Resolve user_did → owner_user_id for per-user filtering
                    let owner_user_id = if !user_did.is_empty() && user_did != "unknown" {
                        // If user_did is already a valid UUID, use it directly (e.g. from an external swarm JWT auth without SSI stack)
                        if uuid::Uuid::parse_str(&user_did).is_ok() {
                            tracing::info!("🔗 Resolved escalation owner directly from user_did UUID: {}", user_did);
                            Some(user_did.clone())
                        } else {
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid {
                                did: user_did.clone(),
                                resp: tx,
                            }).await;
                            match rx.await {
                                Ok(Some(uid)) if !uid.is_empty() => {
                                    tracing::info!("🔗 Resolved escalation owner: {} → user_id={}", user_did, uid);
                                    Some(uid)
                                }
                                _ => {
                                    tracing::warn!("⚠️ Could not resolve user_did {} to user_id", user_did);
                                    None
                                }
                            }
                        }
                    } else {
                        None
                    };

                    // Trust Gateway v5 extensions
                    let tier = parsed.get("tier").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let reason = parsed.get("reason").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let proof_required = parsed.get("proof_required").and_then(|v| v.as_bool()).unwrap_or(false);
                    let proof_request = parsed.get("proof_request").cloned();

                    // Trust Gateway v6 extensions — enriched ActionReview
                    let action_review = parsed.get("action_review").cloned();

                    // Generate a unique reply subject for this request
                    let reply_subject = format!("host.v1.escalation.reply.{}", correlation_id);

                    // Determine initial status based on proof requirement
                    let initial_status = if proof_required { "PENDING_PROOF" } else { "PENDING" };

                    // Lookup conversation context from active_conversations map
                    // (populated by messaging_loop before agent dispatch)
                    let conv_ctx = {
                        if let Ok(map) = shared.active_conversations.lock() {
                            map.get(&requester_did).cloned()
                        } else {
                            None
                        }
                    };

                    // Store in KV
                    let request = crate::dto::EscalationRequest {
                        id: correlation_id.clone(),
                        user_did,
                        tool_name: tool_name.clone(),
                        status: initial_status.to_string(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        nats_reply_subject: reply_subject.clone(),
                        requester_did,
                        owner_user_id,
                        arguments,
                        tier,
                        reason,
                        proof_required,
                        proof_request,
                        approved_by: None,
                        proof_verification: None,
                        action_review,
                        conversation_thid: conv_ctx.as_ref().map(|c| c.thid.clone()),
                        conversation_sender_did: conv_ctx.as_ref().map(|c| c.sender_did.clone()),
                        conversation_inst_did: conv_ctx.as_ref().map(|c| c.inst_did.clone()),
                        conversation_user_id: conv_ctx.as_ref().map(|c| c.user_id.clone()),
                    };

                    if let Some(kv_stores) = &shared.kv_stores {
                        if let Some(store) = kv_stores.get("escalation_requests") {
                            match serde_json::to_vec(&request) {
                                Ok(bytes) => {
                                    let _ = store.put(correlation_id.clone(), bytes.into()).await;
                                    tracing::info!("💾 Stored escalation request '{}' for tool '{}' (tier: {:?}, proof_required: {})", correlation_id, tool_name, request.tier, request.proof_required);
                                }
                                Err(e) => {
                                    tracing::error!("❌ Failed to serialize escalation request: {}", e);
                                }
                            }
                        }
                    }

                    // If the NATS message has a reply-to subject, inform the bridge
                    // of the reply subject it should listen on for the Host's decision.
                    if let Some(reply_to) = msg.reply {
                        let ack = serde_json::json!({
                            "status": "RECEIVED",
                            "reply_subject": reply_subject,
                        });
                        let _ = nats.publish(reply_to.to_string(), serde_json::to_string(&ack).unwrap().into()).await;
                    }
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to escalation requests: {}", e);
            }
        }
    });
}


/// Subscribes to discovery requests from the local MCP NATS bridge.
/// When Agent 2 invokes `discover_agent_services`, the bridge publishes a NATS request
/// to `host.v1.discovery.request`. This handler:
/// 1. Resolves the requester's DID to a user_id.
/// 2. Sends a DIDComm `discover-features/2.0/queries` message to the target DID
///    via the existing `process_send_message_logic` (which handles signing/encryption).
/// 3. Replies to the NATS request to unblock the bridge.
pub fn subscribe_to_discovery_requests(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot subscribe to discovery requests: NATS not available");
        return;
    };

    let shared_clone = shared.clone();
    tokio::spawn(async move {
        let subject = "host.v1.discovery.request";
        tracing::info!("🔍 Subscribing to discovery requests on: {}", subject);

        match nats.subscribe(subject.to_string()).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    let payload_str = String::from_utf8_lossy(&msg.payload).to_string();
                    tracing::info!("🔍 Received discovery request: {}", payload_str);

                    let parsed: serde_json::Value = match serde_json::from_str(&payload_str) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!("❌ Failed to parse discovery request: {}", e);
                            if let Some(reply_to) = msg.reply {
                                let _ = nats.publish(reply_to.to_string(), serde_json::json!({"error": format!("Parse error: {}", e)}).to_string().into()).await;
                            }
                            continue;
                        }
                    };

                    let target_did = parsed["target_did"].as_str().unwrap_or("").to_string();
                    let requester_did = parsed["requester_did"].as_str().unwrap_or("").to_string();
                    let query_thid = parsed["query_thid"].as_str().map(|s| s.to_string());

                    if target_did.is_empty() || requester_did.is_empty() {
                        tracing::error!("❌ Discovery request missing target_did or requester_did");
                        if let Some(reply_to) = msg.reply {
                            let _ = nats.publish(reply_to.to_string(), serde_json::json!({"error": "Missing target_did or requester_did"}).to_string().into()).await;
                        }
                        continue;
                    }

                    // Resolve requester DID to user_id so we can call process_send_message_logic
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let _ = shared_clone.vault_cmd_tx.send(crate::commands::VaultCommand::ResolveDid {
                        did: requester_did.clone(),
                        resp: tx,
                    }).await;

                    let user_id = match rx.await {
                        Ok(Some(uid)) if !uid.is_empty() => uid,
                        _ => {
                            tracing::error!("❌ Could not resolve requester DID: {}", requester_did);
                            if let Some(reply_to) = msg.reply {
                                let _ = nats.publish(reply_to.to_string(), serde_json::json!({"error": "Could not resolve requester DID"}).to_string().into()).await;
                            }
                            continue;
                        }
                    };

                    // Send the DIDComm discover-features query to the target DID
                    let query_body = serde_json::json!({"query": "*"}).to_string();
                    let send_result = crate::handlers::api::process_send_message_logic(
                        shared_clone.clone(),
                        user_id.clone(),
                        Some(requester_did.clone()),
                        target_did.clone(),
                        query_body,
                        "https://didcomm.org/discover-features/2.0/queries".to_string(),
                        query_thid, // Pass the correlation ID if provided by the bridge
                    ).await;

                    match send_result {
                        Ok(_) => {
                            tracing::info!("✅ Discovery query sent from {} to {}", requester_did, target_did);
                            if let Some(reply_to) = msg.reply {
                                let reply = serde_json::json!({
                                    "status": "sent",
                                    "message": format!("Discovery query dispatched to {}. The reply will arrive as a DIDComm message.", target_did)
                                });
                                let _ = nats.publish(reply_to.to_string(), serde_json::to_string(&reply).unwrap().into()).await;
                            }
                        }
                        Err(e) => {
                            tracing::error!("❌ Failed to send discovery query: {}", e);
                            if let Some(reply_to) = msg.reply {
                                let _ = nats.publish(reply_to.to_string(), serde_json::json!({"error": format!("Failed to send: {}", e)}).to_string().into()).await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to discovery requests: {}", e);
            }
        }
    });
}

/// Subscribes to execution results from the Trust Gateway daemon.
///
/// After the daemon dispatches an approved action (e.g., Google Calendar create),
/// it publishes the result to `host.v1.escalation.result`. This listener
/// looks up the original conversation context from the escalation request and
/// delivers the result as a proper DIDComm message in the same chat thread.
pub fn subscribe_to_escalation_results(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot subscribe to escalation results: NATS not available");
        return;
    };

    tokio::spawn(async move {
        let subject = "host.v1.escalation.result";
        tracing::info!("📬 Subscribing to escalation results on: {}", subject);

        match nats.subscribe(subject.to_string()).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    let parsed: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("⚠️ Failed to parse escalation result: {}", e);
                            continue;
                        }
                    };

                    let tool_name = parsed["tool_name"].as_str().unwrap_or("unknown");
                    let status = parsed["status"].as_str().unwrap_or("unknown");
                    let approval_id = parsed["approval_id"].as_str().unwrap_or("");
                    let result_content = parsed["result"]["content"].clone();

                    tracing::info!(
                        "📩 Escalation result: tool='{}', status='{}', approval_id='{}'",
                        tool_name, status, approval_id
                    );

                    // Look up the stored EscalationRequest to get conversation context
                    let escalation = if let Some(kv) = shared.kv_stores.as_ref()
                        .and_then(|m| m.get("escalation_requests"))
                    {
                        if let Ok(Some(entry)) = kv.get(approval_id).await {
                            serde_json::from_slice::<crate::dto::EscalationRequest>(&entry).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let Some(esc) = escalation else {
                        tracing::warn!(
                            "⚠️ Could not find escalation request for approval_id '{}' — cannot route notification",
                            approval_id
                        );
                        continue;
                    };

                    // Extract conversation context (stored deterministically by subscribe_to_escalation_requests)
                    let (thid, sender_did, inst_did, user_id) = match (
                        &esc.conversation_thid,
                        &esc.conversation_sender_did,
                        &esc.conversation_inst_did,
                        &esc.conversation_user_id,
                    ) {
                        (Some(t), Some(s), Some(i), Some(u)) => {
                            (t.clone(), s.clone(), i.clone(), u.clone())
                        }
                        _ => {
                            tracing::warn!(
                                "⚠️ Escalation '{}' missing conversation context — cannot route notification",
                                approval_id
                            );
                            continue;
                        }
                    };

                    // Build notification text
                    let notification_text = if status == "succeeded" {
                        let output_summary = if let Some(arr) = result_content.as_array() {
                            arr.iter()
                                .filter_map(|item| item["text"].as_str())
                                .collect::<Vec<_>>()
                                .join("\n")
                        } else if let Some(s) = result_content.as_str() {
                            s.to_string()
                        } else {
                            result_content.to_string()
                        };

                        if output_summary.is_empty() || output_summary == "null" {
                            format!("✅ Your approved action '{}' has been executed successfully.", tool_name)
                        } else {
                            format!("✅ Your approved action '{}' has been executed successfully.\n\nResult:\n{}", tool_name, output_summary)
                        }
                    } else {
                        format!("❌ Your approved action '{}' failed during execution. Status: {}", tool_name, status)
                    };

                    // Send via process_send_message_logic — same path as normal agent replies.
                    // This ensures the message appears in the correct conversation thread.
                    let body_json = serde_json::json!({ "content": notification_text });
                    match crate::handlers::api::process_send_message_logic(
                        shared.clone(),
                        user_id.clone(),
                        Some(inst_did.clone()),
                        sender_did.clone(),
                        body_json.to_string(),
                        "https://didcomm.org/message/2.0/chat".to_string(),
                        Some(thid.clone()),
                    ).await {
                        Ok(_) => {
                            tracing::info!(
                                "💬 Execution result delivered to {} in thread {} (tool: {})",
                                sender_did, thid, tool_name
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "❌ Failed to deliver execution result to {}: {:?}",
                                sender_did, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to escalation results: {}", e);
            }
        }
    });
}
