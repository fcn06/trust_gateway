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

/// Publish full DID Document to DHT with blind pointer key
/// Stores complete document for proper resolution (verification methods + service endpoints)
pub async fn publish_to_dht(
    kv: &async_nats::jetstream::kv::Store,
    blind_id: &str,
    did_document: &serde_json::Value,
) -> Result<(), String> {
    tracing::info!("🔗 Publishing to DHT: blind_id={} for DID={}", blind_id, did_document["id"]);
    let entry = serde_json::json!({
        "document": did_document,
        "published_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    kv.put(blind_id, serde_json::to_vec(&entry).unwrap().into())
        .await
        .map_err(|e| format!("DHT Put Error: {}", e))?;
    tracing::info!("✅ DHT Publish SUCCESS for blind_id={}", blind_id);
    Ok(())
}

/// Resolve full DID Document from DHT using blind pointer
/// Returns the complete document for verification method lookup and service endpoint resolution
pub async fn resolve_did_document_from_dht(
    kv: &async_nats::jetstream::kv::Store,
    recipient_did: &str,
) -> Option<serde_json::Value> {
    // Sanitize DID
    let recipient_did = if let Some(idx) = recipient_did.find("did:") {
        recipient_did[idx..].trim()
    } else {
        recipient_did.trim()
    };
    
    let blind_id = generate_blind_pointer(recipient_did);
    tracing::info!("🔍 DHT Resolution: checking blind_id {} for DID {}", blind_id, recipient_did);
    match kv.get(&blind_id).await {
        Ok(Some(entry)) => {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&entry) {
                if let Some(doc) = val.get("document") {
                    tracing::info!("✅ DHT Resolution SUCCESS for {}", recipient_did);
                    return Some(doc.clone());
                } else {
                    tracing::warn!("⚠️ DHT Entry found but missing 'document' field");
                }
            } else {
                tracing::warn!("⚠️ DHT Entry found but failed to parse JSON");
            }
            None
        },
        Ok(None) => {
            tracing::warn!("⚠️ DHT Entry NOT FOUND for blind_id {}", blind_id);
            None
        },
        Err(e) => {
            tracing::error!("❌ DHT KV Get Error: {}", e);
            None
        }
    }
}
