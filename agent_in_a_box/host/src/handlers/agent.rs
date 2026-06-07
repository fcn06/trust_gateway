use axum::http::StatusCode;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{info, error, warn};
use serde_json::json;

use crate::audit;

use crate::{
    commands::{AclCommand, VaultCommand},
    shared_state::WebauthnSharedState,
    sovereign::gateway::common_types::Permission,
};

/// Dispatches a message to the local agent (ssi_agent) after verifying ACLs and minting a JWT.
pub async fn dispatch_to_ssi_agent(
    shared: Arc<WebauthnSharedState>,
    sender_did: &str,
    target_user_id: &str,
    message: &str,
    is_institutional: bool,
    thid: Option<String>,
) -> Result<String, (StatusCode, String)> {
    info!("🤖 Delegating message to Agent for user: {}", target_user_id);

    // 1. Verify that the sender has Permission::Agent to talk to this user's agent
    let (tx_acl, rx_acl) = oneshot::channel();
    let _ = shared.acl_cmd_tx.send(AclCommand::CheckPermission {
        owner: target_user_id.to_string(),
        subject: sender_did.to_string(),
        perm: Permission::Agent,
        resp: tx_acl,
    }).await;

    let has_permission = rx_acl.await.unwrap_or(false);
    
    // Always allow self-delegation (if sender is owned by the target user)
    // Also allow if the recipient DID is flagged as Institutional (auto-reply for all)
    let is_self = {
        let (tx_l, rx_l) = oneshot::channel();
        let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(target_user_id.to_string(), tx_l)).await;
        let my_dids = rx_l.await.unwrap_or_default();
        my_dids.contains(&sender_did.to_string())
    };

    if !has_permission && !is_self && !is_institutional {
        warn!("🚫 Access denied: {} does not have Permission::Agent for user {}", sender_did, target_user_id);
        return Err((StatusCode::FORBIDDEN, "Agent access denied by ACL policy".to_string()));
    }

    // 2. Resolve Target User's Active DID (used as issuer constraint)
    let (tx_active, rx_active) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(target_user_id.to_string(), tx_active)).await;
    let target_active_did = rx_active.await.unwrap_or_default();

    if target_active_did.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Target user has no active DID".to_string()));
    }

    // 3. Mint the JWT Session Token via the Vault
    // Scope is determined by the ACLs. Standard clearance by default;
    // elevated clearance is granted via the escalation flow.
    let scope = vec!["mcp:execute".to_string(), "clearance:standard".to_string()];
    let ttl_seconds = shared.config.agent_jwt_ttl_seconds;

    // Resolve tenant_id: use config value if set (multi-tenant), otherwise
    // look up from tenant membership registry (proper multi-tenant).
    let mut tenant_id = if shared.config.tenant_id.is_empty() {
        crate::auth::lookup_user_tenant(&shared, target_user_id).await
            .unwrap_or_default()
    } else {
        shared.config.tenant_id.clone()
    };
    
    if tenant_id.is_empty() {
        tenant_id = "default".to_string();
    }

    let (tx_jwt, rx_jwt) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::IssueSessionJwt {
        user_id: target_user_id.to_string(),
        subject: sender_did.to_string(), // The delegatee
        scope,
        user_did: target_active_did.clone(), // The delegator (issuer)
        ttl_seconds,
        tenant_id: tenant_id.clone(),
        resp: tx_jwt,
    }).await;

    let jwt = match rx_jwt.await {
        Ok(Ok(token)) => token,
        Ok(Err(e)) => {
            error!("❌ Failed to mint Agent JWT: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to issue delegation token".to_string()));
        }
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Vault communication failed".to_string())),
    };

    // === AUDIT: jwt_issued ===
    let mut jti_for_context = sender_did.to_string();
    if let Some((jti, issuer_did)) = audit::extract_jti_from_jwt(&jwt) {
        jti_for_context = jti.clone();
        if let Some(nats) = shared.nats.as_ref() {
            audit::publish_audit(
                nats, &jti, &issuer_did, "jwt_issued", "host",
                json!({ "sender_did": sender_did, "scope": ["mcp:execute"], "ttl": ttl_seconds }),
                Some(&tenant_id),
                Some(target_user_id),
            ).await;
        }
    }    // Register conversation context using JTI for deterministic escalation routing
    {
        let mut map = shared.active_conversations.write().await;
        map.insert(jti_for_context, crate::shared_state::ConversationContext {
            thid: thid.clone().unwrap_or_default(),
            sender_did: sender_did.to_string(),
            inst_did: target_active_did.clone(),
            user_id: target_user_id.to_string(),
        });
    }
    // 4. Construct the payload for ssi_agent using a secure conversation-scoped envelope
    let message_payload = json!({
        "message": message,
        "sender_did": sender_did,
        "channel_type": "UserToAgent",
        "redacted_fields": serde_json::Value::Array(vec![]),
        "conversation_scope": {
            "thread_id": thid.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            "message_count": 1,
            "participants": vec![sender_did.to_string(), target_active_did.clone()],
        },
    });

    let task_id = format!("task-{}", uuid::Uuid::new_v4());
    
    // Construct A2A-compatible JSON-RPC request (tasks/send method)
    let payload = json!({
        "jsonrpc": "2.0",
        "id": uuid::Uuid::new_v4().to_string(),
        "method": "tasks/send",
        "params": {
            "id": task_id,
            "message": {
                "messageId": uuid::Uuid::new_v4().to_string(),
                "role": "user",
                "kind": "message",
                "parts": [
                    {
                        "kind": "text",
                        "text": message_payload.to_string()
                    }
                ],
                "metadata": {
                    "agent_jwt": jwt,
                    "delegator_usid": target_user_id,
                    "delegator_did": target_active_did,
                    "tenant_id": tenant_id
                }
            },
            "historyLength": 50
        }
    });

    // 5. Dispatch via NATS or HTTP
    let nats_dispatch_enabled = std::env::var("NATS_DISPATCH_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true); // Default to NATS dispatch

    // For B2B agents, we might still use HTTP if they are remote, but
    // for local ssi_agent, NATS is preferred. We'll use NATS if enabled
    // and if we have a NATS connection.
    let mut response_body = json!({});
    let mut success = false;

    if nats_dispatch_enabled && shared.nats.is_some() {
        let nats = shared.nats.as_ref().unwrap();
        // NATS Subject format: a2a.v1.<tenant>.tasks.send or a2a.v1.<tenant>.b2b.send
        let safe_tenant = tenant_id.replace(':', "_");
        
        let subject = format!("a2a.v1.{}.tasks.send", safe_tenant);
        
        info!("🚀 Sending NATS request to {}", subject);
        
        // Wrap payload in a message that includes the JWT in headers or payload
        // The ssi_agent NATS subscriber will need to extract it. We'll send the raw JSON
        // but ensure the JWT is in the metadata (which we already did above).
        let nats_payload = serde_json::to_vec(&payload).unwrap_or_default();
        
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            nats.request(subject, nats_payload.into())
        ).await {
            Ok(Ok(msg)) => {
                if let Ok(res_json) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                    if res_json.get("error").is_some() {
                        error!("❌ ssi_agent NATS returned error: {}", serde_json::to_string(&res_json).unwrap_or_default());
                        return Err((StatusCode::BAD_GATEWAY, "Agent execution failed".to_string()));
                    }
                    response_body = res_json;
                    success = true;
                    info!("✅ ssi_agent NATS response received");
                } else {
                    error!("❌ Invalid JSON from ssi_agent NATS");
                    return Err((StatusCode::BAD_GATEWAY, "Invalid Agent response".to_string()));
                }
            }
            Ok(Err(e)) => {
                error!("❌ NATS request to ssi_agent failed: {}", e);
                // Fall back to HTTP below
                info!("⚠️ Falling back to HTTP dispatch...");
            }
            Err(_) => {
                error!("❌ NATS request to ssi_agent timed out");
                return Err((StatusCode::GATEWAY_TIMEOUT, "Agent execution timed out".to_string()));
            }
        }
    }

    // HTTP Fallback
    if !success {
        let endpoint = shared.config.ssi_agent_endpoint.trim_end_matches('/').to_string() + "/";
        let client = shared.http_client.clone();
        
        info!("🚀 Sending HTTP request to ssi_agent at {}", endpoint);
        let resp = client.post(&endpoint)
            .header("Authorization", format!("Bearer {}", jwt))
            .json(&payload)
            .send()
            .await;

        match resp {
            Ok(res) if res.status().is_success() => {
                response_body = res.json().await.unwrap_or(json!({}));
                success = true;
                info!("✅ ssi_agent HTTP response received");
            }
            Ok(res) => {
                error!("❌ ssi_agent HTTP returned error status: {}", res.status());
                return Err((StatusCode::BAD_GATEWAY, format!("Agent execution failed: {}", res.status())));
            }
            Err(e) => {
                error!("❌ HTTP error connecting to ssi_agent: {}", e);
                return Err((StatusCode::SERVICE_UNAVAILABLE, "Agent orchestrator unreachable".to_string()));
            }
        }
    }

    if success {
        let agent_text = response_body["result"]["status"]["message"]["parts"]
            .as_array()
            .and_then(|parts| parts.first())
            .and_then(|part| part["text"].as_str())
            .unwrap_or("No textual response from agent");
            
        info!("🤖 Agent response extracted: {}", agent_text);

        // === AUDIT: request_dispatched ===
        if let Some(nats) = shared.nats.as_ref() {
            if let Some((jti, issuer_did)) = audit::extract_jti_from_jwt(&jwt) {
                audit::publish_audit(
                    nats, &jti, &issuer_did, "request_dispatched", "host",
                    json!({ "result": "success", "sender_did": sender_did }),
                    Some(&tenant_id),
                    Some(target_user_id),
                ).await;
            }
        }

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        
        if !is_institutional {
            let msg = crate::dto::PlainDidcommDto {
                id: uuid::Uuid::new_v4().to_string(),
                r#type: "https://didcomm.org/self-note/1.0/note".to_string(),
                from: Some(sender_did.to_string()),
                to: Some(vec![sender_did.to_string()]),
                thid: thid.clone(),
                body: json!({ "content": agent_text }),
                created_time: Some(now),
                expires_time: None,
                status: Some("distributed".to_string()),
                envelope: None,
                alias: Some("AI Agent".to_string()),
                channel_type: Some("AgentToUser".to_string()),
                provenance: None,
            };

            if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
                if let Ok(val) = serde_json::to_vec(&msg) {
                    let key = format!("{}_{}", sender_did.replace(":", "_"), msg.id);
                    let _ = kv.put(key, val.into()).await;
                }
            }
        }

        return Ok(agent_text.to_string());
    }

    Err((StatusCode::INTERNAL_SERVER_ERROR, "Unexpected dispatcher state".to_string()))
}
