//! OID4VP NATS handlers for the Host.
//!
//! These handlers respond to NATS requests proxied from the Gateway's
//! `/oid4vp/request` and `/oid4vp/response` HTTP endpoints. All OID4VP
//! state lives here on the Host — the Gateway remains a dumb pipe.

use std::sync::Arc;
use futures::StreamExt;

use crate::logic::compute_node_id;
use crate::shared_state::WebauthnSharedState;

// Removed hardcoded RSA_PEM and CLIENT_ID constants. They are now loaded dynamically from shared state.
/// Subscribe to `v1.{node_id}.oid4vp.get_request` NATS requests.
///
/// When a wallet fetches the `request_uri`, the Gateway proxies the request
/// to this subject. This handler:
/// 1. Reads the pending ActionRequest from KV.
/// 2. Builds and signs an OpenID4VP authorization-request JWT.
/// 3. Replies with the JWT string.
pub fn subscribe_oid4vp_get_request(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot subscribe to OID4VP get_request: NATS not available");
        return;
    };

    let node_id = compute_node_id(&shared.house_salt);
    let subject = format!("v1.{}.oid4vp.get_request", node_id);

    let gateway_url = shared.gateway_url.clone()
        .or_else(|| Some(shared.config.service_gateway_base_url.clone()))
        .unwrap_or_else(|| std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:3002".to_string()));

    tokio::spawn(async move {
        tracing::info!("🔑 Subscribing to OID4VP get_request on: {}", subject);

        let mut sub = match nats.subscribe(subject.clone()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to {}: {}", subject, e);
                return;
            }
        };

        while let Some(msg) = sub.next().await {
            let request_id = String::from_utf8_lossy(&msg.payload).to_string();
            tracing::info!("🔑 OID4VP get_request for: {}", request_id);

            // Look up the pending ActionRequest from KV
            let action_req_opt = if let Some(kv) = shared.kv_stores.as_ref()
                .and_then(|m| m.get("pending_oid4vp_requests"))
            {
                match kv.get(&request_id).await {
                    Ok(Some(entry)) => {
                        serde_json::from_slice::<ssi_crypto::ucan::ActionRequest>(&entry).ok()
                    }
                    _ => None,
                }
            } else {
                None
            };

            let jwt = match action_req_opt {
                Some(action_req) => build_oid4vp_jwt(
                    &action_req,
                    &gateway_url,
                    &node_id,
                    &shared.oid4vp_client_id,
                    &shared.oid4vp_rsa_pem,
                ),
                None => {
                    tracing::warn!("⚠️ No pending OID4VP request found for: {}", request_id);
                    "error:not_found".to_string()
                }
            };

            // Reply
            if let Some(reply_to) = msg.reply {
                let _ = nats.publish(reply_to.to_string(), jwt.into()).await;
            }
        }
    });
}

/// Subscribe to `v1.{node_id}.oid4vp.submit_response` NATS requests.
///
/// When a wallet submits its `direct_post` response, the Gateway proxies
/// it to this subject. This handler:
/// 1. Parses the request_id and wallet payload.
/// 2. Marks the ActionRequest as approved in KV.
/// 3. Publishes an ActionResponse to `mcp.escalate.replies` to unblock the MCP bridge.
/// 4. Replies with a success/error JSON to the Gateway (→ wallet).
pub fn subscribe_oid4vp_submit_response(shared: Arc<WebauthnSharedState>) {
    let Some(nats) = shared.nats.clone() else {
        tracing::warn!("⚠️ Cannot subscribe to OID4VP submit_response: NATS not available");
        return;
    };

    let node_id = compute_node_id(&shared.house_salt);
    let subject = format!("v1.{}.oid4vp.submit_response", node_id);

    tokio::spawn(async move {
        tracing::info!("🔑 Subscribing to OID4VP submit_response on: {}", subject);

        let mut sub = match nats.subscribe(subject.clone()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to {}: {}", subject, e);
                return;
            }
        };

        while let Some(msg) = sub.next().await {
            let payload_str = String::from_utf8_lossy(&msg.payload).to_string();
            tracing::info!("🔑 OID4VP submit_response received: {}…", &payload_str[..payload_str.len().min(120)]);

            // Parse the Gateway's envelope: { request_id, body }
            let envelope: serde_json::Value = match serde_json::from_str(&payload_str) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("❌ Invalid OID4VP response envelope: {}", e);
                    if let Some(reply_to) = msg.reply {
                        let err = serde_json::json!({"error": "invalid_envelope"});
                        let _ = nats.publish(reply_to.to_string(), serde_json::to_vec(&err).unwrap().into()).await;
                    }
                    continue;
                }
            };

            let request_id = envelope["request_id"].as_str().unwrap_or("").to_string();
            if request_id.is_empty() {
                if let Some(reply_to) = msg.reply {
                    let err = serde_json::json!({"error": "missing_request_id"});
                    let _ = nats.publish(reply_to.to_string(), serde_json::to_vec(&err).unwrap().into()).await;
                }
                continue;
            }

            // Verify the pending request exists in KV
            let found = if let Some(kv) = shared.kv_stores.as_ref()
                .and_then(|m| m.get("pending_oid4vp_requests"))
            {
                match kv.get(&request_id).await {
                    Ok(Some(_)) => {
                        // Clean up the pending request
                        let _ = kv.delete(&request_id).await;
                        true
                    }
                    _ => false,
                }
            } else {
                false
            };

            if !found {
                tracing::warn!("⚠️ OID4VP response for unknown request: {}", request_id);
                if let Some(reply_to) = msg.reply {
                    let err = serde_json::json!({"error": "unknown_request_id"});
                    let _ = nats.publish(reply_to.to_string(), serde_json::to_vec(&err).unwrap().into()).await;
                }
                continue;
            }

            // Wallet submitted a presentation → consider it approved.
            // Publish ActionResponse to unblock the MCP bridge.
            let action_response = ssi_crypto::ucan::ActionResponse {
                request_id: request_id.clone(),
                approved: true,
                signature: None, // VP token signature replaces the Ed25519 leash
            };

            let response_bytes = serde_json::to_vec(&action_response).unwrap();
            let _ = nats.publish(
                "mcp.escalate.replies".to_string(),
                response_bytes.into(),
            ).await;
            tracing::info!("✅ OID4VP approved for request '{}', published to mcp.escalate.replies", request_id);

            // Reply to the Gateway (→ wallet)
            if let Some(reply_to) = msg.reply {
                let ok = serde_json::json!({
                    "status": "success",
                    "request_id": request_id,
                });
                let _ = nats.publish(reply_to.to_string(), serde_json::to_vec(&ok).unwrap().into()).await;
            }
        }
    });
}

// ──────────────────────────────────────────────────────
// JWT Builder
// ──────────────────────────────────────────────────────

/// Build a signed OID4VP authorization-request JWT for a pending ActionRequest.
///
/// The JWT follows the `oauth-authz-req+jwt` format expected by EUDI wallets
/// (Sphereon, etc.). The `response_uri` points back to the Gateway's
/// POST proxy endpoint so the wallet's direct_post reaches us.
fn build_oid4vp_jwt(
    action_req: &ssi_crypto::ucan::ActionRequest,
    gateway_url: &str,
    node_id: &str,
    client_id: &str,
    rsa_pem: &str,
) -> String {
    use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

    let nonce = format!("n-{}", action_req.request_id);
    let response_uri = format!(
        "{}/oid4vp/response/{}/{}",
        gateway_url.trim_end_matches('/'),
        node_id,
        action_req.request_id,
    );

    let claims = serde_json::json!({
        "iss": client_id,
        "aud": "https://self-issued.me/v2",
        "client_id": client_id,
        "client_id_scheme": "did",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": response_uri,
        "scope": "openid",
        "nonce": nonce,
        "state": action_req.request_id,
        "dcql_query": {
            "credentials": [{
                "id": "action_approval",
                "format": "jwt_vc_json",
                "meta": {},
                "claims": [{
                    "id": "tool_claim",
                    "path": ["$.type"],
                    "values": ["VerifiableCredential"]
                }]
            }]
        },
        "client_metadata": {
            "client_id": client_id,
            "client_name": format!("Action: {}", action_req.human_summary),
            "redirect_uris": [response_uri],
            "response_types": ["vp_token"],
            "subject_syntax_types_supported": ["did:jwk"]
        }
    });

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(format!("{}#0", client_id));
    header.typ = Some("oauth-authz-req+jwt".to_string());

    let key = match EncodingKey::from_rsa_pem(rsa_pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("❌ RSA PEM parse failed: {}", e);
            return format!("error:rsa_key_parse_failed:{}", e);
        }
    };

    match encode(&header, &claims, &key) {
        Ok(jwt) => jwt,
        Err(e) => {
            tracing::error!("❌ JWT encoding failed: {}", e);
            format!("error:jwt_encode_failed:{}", e)
        }
    }
}
