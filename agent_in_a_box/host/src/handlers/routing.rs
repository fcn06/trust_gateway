// ─────────────────────────────────────────────────────────────
// Message Routing Strategies
//
// Extracted from process_send_message_logic to reduce complexity.
// Each strategy attempts to deliver a DIDComm envelope to a
// recipient via a specific transport. Strategies are tried in
// priority order; some are non-exclusive (local NATS + contact
// store can both succeed).
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use tokio::sync::oneshot;

use crate::shared_state::WebauthnSharedState;
use crate::commands::{VaultCommand, ContactStoreCommand};
use crate::logic::resolve_did_document_from_dht;

/// Context shared across all routing strategies for a single message dispatch.
pub struct RoutingContext {
    pub shared: Arc<WebauthnSharedState>,
    pub recipient: String,
    pub envelope: String,
}

/// Strategy 1: Local NATS shortcut.
///
/// If the recipient is registered on the same host, publish directly
/// to the local NATS subject. This is non-exclusive — even if it
/// succeeds, contact_store resolution will still be attempted.
pub async fn try_local_nats(ctx: &RoutingContext) -> bool {
    let target_id = crate::logic::compute_local_subject(&ctx.recipient, &ctx.shared.house_salt);
    let is_local = {
        let map = ctx.shared.target_id_map.read().await;
        map.contains_key(&target_id)
    };

    if !is_local {
        return false;
    }

    if let Some(nc) = &ctx.shared.nats {
        let node_id = crate::logic::compute_node_id(&ctx.shared.house_salt);
        let subject = if ctx.shared.config.tenant_id.is_empty() {
            format!("v1.{}.didcomm.{}", node_id, target_id)
        } else {
            format!("v1.{}.{}.didcomm.{}", ctx.shared.config.tenant_id, node_id, target_id)
        };
        let _ = nc.publish(subject.clone(), ctx.envelope.clone().into()).await;
        tracing::info!("📢 Published to local NATS subject: {}", subject);
        return true;
    }

    false
}

/// Strategy 2: Contact Store resolution (Ledgerless).
///
/// Looks up the recipient's DID Document in the local contact_store
/// (exchanged during handshake) and sends via the MessagingGateway endpoint.
pub async fn try_contact_store(ctx: &RoutingContext) -> bool {
    let (cs_tx, cs_rx) = oneshot::channel();
    let _ = ctx.shared.contact_cmd_tx.send(ContactStoreCommand::GetContact {
        did: ctx.recipient.clone(),
        resp: cs_tx,
    }).await;
    
    if let Ok(Some(did_doc)) = cs_rx.await {
        tracing::info!("📇 Resolved recipient from contact_store: {}", ctx.recipient);
        
        if let Some(svc) = did_doc.service_endpoints.iter().find(|s| {
            s.type_ == "MessagingGateway" || s.type_ == "MessagingService" || s.type_ == "DIDCommMessaging"
        }) {
            let endpoint = &svc.endpoint;
            tracing::info!("📤 Sending via contact_store endpoint: {}", endpoint);
            
            let client = ctx.shared.http_client.clone();
            match client.post(endpoint).body(ctx.envelope.clone()).send().await {
                Ok(res) if res.status().is_success() => {
                    tracing::info!("✅ Sent via contact_store-resolved endpoint");
                    return true;
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

    false
}

/// Strategy 3: DHT Discovery (Legacy).
///
/// Resolves the recipient's DID Document from the distributed hash table
/// and delivers via the resolved service endpoint (NATS, HTTP, Wallet WS,
/// or JIT Gateway routing).
pub async fn try_dht_discovery(ctx: &RoutingContext) -> bool {
    let kv_stores = match &ctx.shared.kv_stores {
        Some(stores) => stores,
        None => return false,
    };
    let dht_store = match kv_stores.get("dht_discovery") {
        Some(s) => s,
        None => return false,
    };

    let doc = match resolve_did_document_from_dht(dht_store, &ctx.recipient).await {
        Some(d) => d,
        None => return false,
    };

    tracing::info!("📄 Resolved DID Doc for routing");

    let service = match doc["service"].as_array()
        .and_then(|services| services.iter().find(|s| {
            s["type"] == "MessagingService" || s["type"] == "DIDCommMessaging"
        })) {
        Some(s) => s,
        None => {
            tracing::warn!("⚠️ No MessagingService found in DID Doc or serviceEndpoint is missing/invalid");
            return false;
        }
    };

    let service_endpoint = &service["serviceEndpoint"];

    // Branch A: Direct string endpoint (legacy, NATS, wallet WS)
    if let Some(endpoint_str) = service_endpoint.as_str() {
        return deliver_via_direct_endpoint(ctx, endpoint_str).await;
    }

    // Branch B: JIT routing object endpoint
    if let Some(endpoint_obj) = service_endpoint.as_object() {
        return deliver_via_jit_routing(ctx, endpoint_obj, dht_store).await;
    }

    false
}

/// Deliver via a direct string endpoint (legacy HTTP, NATS, or Wallet WS).
async fn deliver_via_direct_endpoint(ctx: &RoutingContext, endpoint_str: &str) -> bool {
    tracing::info!("Use legacy endpoint: {}", endpoint_str);

    // Wallet WebSocket push
    if endpoint_str.contains("/ws/wallet") {
        if let Some(nc) = &ctx.shared.nats {
            let push_payload = serde_json::json!({
                "recipient_did": ctx.recipient,
                "type": "chat_message",
                "envelope": ctx.envelope
            });
            if let Ok(bytes) = serde_json::to_vec(&push_payload) {
                if nc.publish("gateway.push.wallet".to_string(), bytes.into()).await.is_ok() {
                    tracing::info!("📤 Pushed DIDComm reply to online Wallet via Gateway WS");
                    return true;
                }
            }
        }
        return false;
    }

    // NATS endpoint
    if endpoint_str.starts_with("nats://") {
        let subject = endpoint_str.split('/').last().unwrap_or(endpoint_str);
        if let Some(nc) = &ctx.shared.nats {
            match nc.publish(subject.to_string(), ctx.envelope.clone().into()).await {
                Ok(_) => {
                    tracing::info!("📤 Sent via DHT-resolved NATS endpoint: {}", subject);
                    return true;
                },
                Err(e) => tracing::error!("❌ NATS Publish failed: {}", e),
            }
        }
        return false;
    }

    // HTTP endpoint
    let client = ctx.shared.http_client.clone();
    match client.post(endpoint_str).body(ctx.envelope.clone()).send().await {
        Ok(res) if res.status().is_success() => {
            tracing::info!("📤 Sent via DHT-resolved HTTP endpoint");
            true
        },
        Ok(res) => {
            tracing::error!("❌ HTTP Post failed with status: {}", res.status());
            false
        },
        Err(e) => {
            tracing::error!("❌ HTTP Post failed: {}", e);
            false
        },
    }
}

/// Deliver via JIT Gateway Routing (resilient coordination with encrypted routing token).
async fn deliver_via_jit_routing(
    ctx: &RoutingContext,
    endpoint_obj: &serde_json::Map<String, serde_json::Value>,
    dht_store: &async_nats::jetstream::kv::Store,
) -> bool {
    let uri = endpoint_obj.get("uri").and_then(|v| v.as_str()).unwrap_or_default();
    let routing_did = endpoint_obj.get("routing_did").and_then(|v| v.as_str()).unwrap_or_default();
    let target_id_blob = endpoint_obj.get("target_id").and_then(|v| v.as_str()).unwrap_or_default();

    if uri.is_empty() || routing_did.is_empty() || target_id_blob.is_empty() {
        tracing::error!("❌ Incomplete JIT serviceEndpoint object");
        return false;
    }

    tracing::info!("🔏 Resolving Gateway DID: {}", routing_did);

    // 1. Resolve Gateway Public Key from DHT
    let gw_doc = match resolve_did_document_from_dht(dht_store, routing_did).await {
        Some(d) => d,
        None => {
            tracing::error!("❌ Could not resolve Gateway DID: {}", routing_did);
            return false;
        }
    };

    let gw_pub_key = gw_doc["verificationMethod"].as_array()
        .and_then(|vms| vms.iter().find(|v| v["id"].as_str().unwrap_or_default().contains("routing-key")))
        .and_then(|vm| vm["publicKeyBase64"].as_str());

    let pub_key = match gw_pub_key {
        Some(k) => k,
        None => {
            tracing::error!("❌ Gateway DID Doc found but missing routingKey");
            return false;
        }
    };

    // 2. Generate Transient JIT Token via Vault
    let (tx_j, rx_j) = oneshot::channel();
    let _ = ctx.shared.vault_cmd_tx.send(VaultCommand::EncryptRoutingToken { 
        routing_key: pub_key.to_string(), 
        target_id: target_id_blob.to_string(), 
        resp: tx_j 
    }).await;

    let token = match rx_j.await {
        Ok(Ok(t)) => t,
        _ => {
            tracing::error!("❌ Failed to encrypt JIT token locally");
            return false;
        }
    };

    tracing::info!("🔒 JIT Encryption SUCCESS. Dispatching to: {}", uri);
    let client = ctx.shared.http_client.clone();

    // Payload validation trace
    if let Ok(json_env) = serde_json::from_str::<serde_json::Value>(&ctx.envelope) {
        if json_env.is_object() {
            tracing::info!("✅ Payload is valid JSON object (DIDComm v2 structure check passed)");
        } else {
            tracing::warn!("⚠️ Payload is NOT a JSON object - valid DIDComm v2 messages should be JWE/JWS JSON objects.");
        }
    } else {
        tracing::warn!("⚠️ Payload is NOT valid JSON - valid DIDComm v2 messages should be JWE/JWS JSON.");
    }

    match client.post(uri).header("X-Routing-Token", token.clone()).body(ctx.envelope.clone()).send().await {
        Ok(res) if res.status().is_success() => {
            tracing::info!("📤 Sent via JIT Gateway Routing");
            true
        },
        Ok(res) => {
            tracing::error!("❌ JIT Gateway Post failed: {}", res.status());
            false
        },
        Err(e) => {
            tracing::error!("❌ JIT Gateway Post error: {}", e);
            false
        },
    }
}

/// Strategy 4: DID Ledger fallback.
///
/// Last-resort lookup in the local `did_ledger` KV bucket.
pub async fn try_did_ledger(ctx: &RoutingContext) -> bool {
    let kv_stores = match &ctx.shared.kv_stores {
        Some(stores) => stores,
        None => return false,
    };
    let store = match kv_stores.get("did_ledger") {
        Some(s) => s,
        None => return false,
    };

    let encoded_key = hex::encode(&ctx.recipient);
    let entry = match store.get(encoded_key).await {
        Ok(Some(e)) => e,
        _ => return false,
    };

    let doc = match serde_json::from_slice::<serde_json::Value>(&entry) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let endpoint = match doc["service"].as_array()
        .and_then(|services| services.iter().find(|s| s["type"] == "MessagingService"))
        .and_then(|service| service["serviceEndpoint"].as_str()) {
        Some(e) => e,
        None => return false,
    };

    if endpoint.starts_with("nats://") {
        let subject = endpoint.split('/').last().unwrap_or(endpoint);
        if let Some(nc) = &ctx.shared.nats {
            if nc.publish(subject.to_string(), ctx.envelope.clone().into()).await.is_ok() {
                tracing::info!("📤 Sent via did_ledger endpoint: {}", subject);
                return true;
            }
        }
    } else {
        let client = ctx.shared.http_client.clone();
        if let Ok(res) = client.post(endpoint).body(ctx.envelope.clone()).send().await {
            if res.status().is_success() {
                return true;
            }
        }
    }

    false
}

/// Persist a successfully distributed message to sovereign_kv and record
/// outgoing contact requests.
pub async fn persist_distributed_message(
    shared: &Arc<WebauthnSharedState>,
    dto: &super::api::PlainDidcommDto,
    msg_id: &str,
    typ: &str,
    sender_did: &str,
    recipient: &str,
    message: &str,
) {
    // Store the message itself
    if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("sovereign_kv")) {
        if let Ok(val) = serde_json::to_vec(dto) {
            let _ = kv.put(msg_id.to_string(), val.into()).await;
            // Index by thid for O(1) lookup by check_handshake_status_handler
            if let Some(ref thid) = dto.thid {
                let _ = kv.put(format!("thid_{}", thid), msg_id.as_bytes().to_vec().into()).await;
            }
        }
    }
    
    // Track outgoing contact requests for acceptance flow
    if typ == "https://lianxi.io/protocols/contact/1.0/request" {
        if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("contact_requests")) {
            let req_id = uuid::Uuid::new_v4().to_string();
            let now_str = chrono::Utc::now().to_rfc3339();
            let pending_req = crate::dto::ContactRequest {
                id: req_id.clone(),
                owner_did: sender_did.to_string(), 
                sender_did: recipient.to_string(),
                role: Some("OUTGOING".to_string()),
                request_msg: serde_json::json!({ "message": message }),
                status: "PENDING".to_string(),
                created_at: now_str,
            };
            if let Ok(bytes) = serde_json::to_vec(&pending_req) {
                let _ = kv.put(req_id, bytes.into()).await;
            }
            tracing::info!("📝 Recorded OUTGOING contact request from {} to {}", sender_did, recipient);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Unit Tests — Message Routing
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::mocks::mock_shared_state;

    #[tokio::test]
    async fn test_try_local_nats_non_local() {
        let shared = mock_shared_state();
        let ctx = RoutingContext {
            shared,
            recipient: "did:twin:remote".to_string(),
            envelope: "test-envelope".to_string(),
        };

        let result = try_local_nats(&ctx).await;
        assert!(!result); // Should be false because recipient is not in target_id_map
    }

    #[tokio::test]
    async fn test_try_local_nats_is_local_no_nats() {
        let shared = mock_shared_state();
        let recipient = "did:twin:local".to_string();
        let target_id = crate::logic::compute_local_subject(&recipient, &shared.house_salt);
        
        {
            let mut map = shared.target_id_map.write().await;
            map.insert(target_id, "user-123".to_string());
        }

        let ctx = RoutingContext {
            shared: shared.clone(),
            recipient,
            envelope: "test-envelope".to_string(),
        };

        let result = try_local_nats(&ctx).await;
        // Should be false because shared.nats is None in mock_shared_state
        assert!(!result);
    }
}
