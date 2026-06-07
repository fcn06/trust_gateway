// No longer uses local Deserialize/Serialize after consolidating DTOs
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use hex;

// use crate::dto::*;

// === Logic Functions ===

pub fn compute_local_subject(did: &str, secret: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC error");
    mac.update(did.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn calculate_blind_key(key: &str, salt: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC error");
    mac.update(key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn compute_node_id(house_salt: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(house_salt).expect("HMAC error");
    mac.update(b"sovereign-node-id");
    hex::encode(mac.finalize().into_bytes())
}

/// Compute a deterministic target ID from a DID for JIT routing.
/// Uses HMAC(house_salt, "target:" || did) to derive a short opaque identifier.
pub fn compute_target_id(did: &str, house_salt: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(house_salt).expect("HMAC error");
    mac.update(b"target:");
    mac.update(did.as_bytes());
    let hash = hex::encode(mac.finalize().into_bytes());
    // Use first 16 chars for a shorter target ID
    hash[..16].to_string()
}

// === DHT Discovery Functions ===

/// Generate a deterministic pointer for DHT discovery based on SHA256(DID)
pub fn generate_blind_pointer(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    hex::encode(hasher.finalize())
}

/// Publish full DID Document to DHT (HTTP to Gateway + Local Cache)
/// Stores complete document for proper resolution.
pub async fn publish_to_dht(
    http_client: &reqwest::Client,
    gateway_base_url: &str,
    kv: Option<&async_nats::jetstream::kv::Store>,
    did_document: &serde_json::Value,
    signed_payload: Option<String>,
) -> Result<(), String> {
    let did = did_document["id"].as_str().unwrap_or_default();
    let blind_id = generate_blind_pointer(did);
    tracing::info!("🔗 Publishing DID={} to DHT (HTTP)", did);

    // 1. Try to publish via HTTP to Gateway (only if a signed envelope is available, as the gateway requires it)
    if !gateway_base_url.is_empty() && signed_payload.is_some() {
        let base = gateway_base_url
            .trim_end_matches('/')
            .trim_end_matches("ingress")
            .trim_end_matches('/');
            
        let publish_url = format!("{}/publish", base);
        
        let publish_payload = if let Some(sig) = signed_payload {
            serde_json::json!({ "signed_document": sig })
        } else {
            // Unsigned fallback (e.g. for Gateway's own DID self-healing)
            serde_json::json!({ "document": did_document })
        };
        
        match http_client.post(&publish_url).json(&publish_payload).send().await {
            Ok(res) if res.status().is_success() => {
                tracing::info!("✅ Gateway HTTP publish succeeded for {}", did);
            },
            Ok(res) => {
                tracing::warn!("⚠️ Gateway HTTP publish returned status {}: {}", res.status(), res.text().await.unwrap_or_default());
            },
            Err(e) => {
                tracing::warn!("⚠️ Gateway HTTP publish network error: {}", e);
            }
        }
    }

    // 2. Write to Local Cache for Resilience
    if let Some(store) = kv {
        let entry = serde_json::json!({
            "document": did_document,
            "published_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        if let Err(e) = store.put(blind_id.clone(), serde_json::to_vec(&entry).unwrap().into()).await {
            tracing::warn!("⚠️ Failed to cache DHT entry locally for {}: {}", did, e);
        } else {
            tracing::debug!("✅ Cached DHT entry locally for {}", did);
        }
    }

    Ok(())
}

/// Resolve full DID Document from DHT (HTTP to Gateway with Local Cache Fallback)
pub async fn resolve_did_document_from_dht(
    http_client: &reqwest::Client,
    gateway_base_url: &str,
    kv: Option<&async_nats::jetstream::kv::Store>,
    recipient_did: &str,
) -> Option<serde_json::Value> {
    // Sanitize DID
    let recipient_did = if let Some(idx) = recipient_did.find("did:") {
        recipient_did[idx..].trim()
    } else {
        recipient_did.trim()
    };
    
    let blind_id = generate_blind_pointer(recipient_did);
    tracing::info!("🔍 DHT Resolution: resolving {}", recipient_did);

    // 1. HTTP Resolution from Gateway
    if !gateway_base_url.is_empty() {
        let base = gateway_base_url
            .trim_end_matches('/')
            .trim_end_matches("ingress")
            .trim_end_matches('/');
            
        let url = format!("{}/did/{}", base, recipient_did);
        
        if let Ok(res) = http_client.get(&url).send().await {
            if res.status().is_success() {
                if let Ok(doc) = res.json::<serde_json::Value>().await {
                    tracing::info!("✅ HTTP Resolution SUCCESS for {}", recipient_did);
                    
                    // Update Local Cache
                    if let Some(store) = kv {
                        let entry = serde_json::json!({
                            "document": &doc,
                            "published_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
                        });
                        let _ = store.put(blind_id.clone(), serde_json::to_vec(&entry).unwrap().into()).await;
                    }
                    
                    return Some(doc);
                }
            }
        }
        tracing::warn!("⚠️ HTTP Resolution FAILED for {}, falling back to local cache", recipient_did);
    }

    // 2. Local Cache Fallback
    if let Some(store) = kv {
        match store.get(&blind_id).await {
            Ok(Some(entry)) => {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&entry) {
                    if let Some(doc) = val.get("document") {
                        tracing::info!("✅ Local Cache Resolution SUCCESS for {}", recipient_did);
                        return Some(doc.clone());
                    }
                }
            },
            _ => {}
        }
    }
    
    tracing::warn!("❌ DHT Resolution completely failed for {}", recipient_did);
    None
}
