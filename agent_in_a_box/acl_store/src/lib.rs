wit_bindgen::generate!({
    world: "acl-store",
    path: "../wit",
    additional_derives: [serde::Serialize, serde::Deserialize],
});

use crate::exports::sovereign::gateway::acl::Guest;
use sovereign::gateway::common_types::{Permission, ConnectionPolicy, ConnectionStatus};
use sovereign::gateway::persistence;
use sovereign::gateway::vault;
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use sha2::Sha256;
use chacha20poly1305::{
    aead::{Aead, KeyInit as _},
    XChaCha20Poly1305, XNonce
};
use hkdf::Hkdf;
use hex;

struct AclStore;

impl Guest for AclStore {
    fn check_permission(owner: String, subject: String, perm: Permission) -> bool {
        let key = format!("{}:{}", owner, subject);
        if let Ok(Some(value)) = blind_get(&key, &owner) {
            if let Ok(policy) = serde_json::from_slice::<ConnectionPolicy>(&value) {
                if policy.status != ConnectionStatus::Active {
                    return false;
                }
                
                for p in &policy.permissions {
                    if *p == perm {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn update_policy(owner: String, policy: ConnectionPolicy) -> Result<bool, String> {
        let key = format!("{}:{}", owner, policy.did);
        let value = serde_json::to_vec(&policy).map_err(|e| e.to_string())?;
        blind_set(&key, &value, &owner)?;
        
        // Add to index
        let b_key = blind_key(&key);
        let index_key_raw = format!("{}:index", owner);
        let b_index_key = blind_key(&index_key_raw);
        
        let mut index: Vec<String> = match persistence::get(&b_index_key) {
            Ok(Some(idx_bytes)) => serde_json::from_slice(&idx_bytes).unwrap_or_default(),
            _ => Vec::new(),
        };
        
        if !index.contains(&b_key) {
            index.push(b_key);
            let _ = persistence::set(&b_index_key, &serde_json::to_vec(&index).unwrap());
        }

        Ok(true)
    }

    fn get_policies(owner: String) -> Vec<ConnectionPolicy> {
        let mut policies = Vec::new();
        let index_key_raw = format!("{}:index", owner);
        let b_index_key = blind_key(&index_key_raw);
        
        if let Ok(Some(idx_bytes)) = persistence::get(&b_index_key) {
            if let Ok(index) = serde_json::from_slice::<Vec<String>>(&idx_bytes) {
                for b_key in index {
                    if let Ok(Some(value)) = blind_get_by_blind_key(&b_key, &owner) {
                        if let Ok(policy) = serde_json::from_slice::<ConnectionPolicy>(&value) {
                            policies.push(policy);
                        }
                    }
                }
            }
        }
        
        policies
    }
}

// === UCAN DelegationGrant Storage ===
// These are additional host-side helpers that store UCAN token chains
// alongside the flat permission model. The WIT interface remains unchanged;
// the Host calls these via the same blind persistence KV.

/// A UCAN delegation grant stored alongside connection policies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DelegationGrant {
    /// The UCAN token (JWT string or serialized JSON)
    token: String,
    /// Resource being granted (e.g., "messaging", "process_refund")
    resource: String,
    /// Action being granted (e.g., "execute", "read")
    action: String,
    /// Expiry timestamp (0 = no expiry)
    expires_at: u64,
    /// If true, was approved via ActionResponse (not pre-delegated)
    runtime_approved: bool,
}

/// Store a delegation grant for a connection.
fn store_delegation(owner: &str, subject: &str, grant: &DelegationGrant) -> Result<(), String> {
    let key = format!("{}:ucan:{}", owner, subject);
    
    // Load existing grants
    let mut grants: Vec<DelegationGrant> = if let Ok(Some(val)) = blind_get(&key, owner) {
        serde_json::from_slice(&val).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    // De-duplicate by resource+action
    grants.retain(|g| g.resource != grant.resource || g.action != grant.action);
    grants.push(grant.clone());
    
    let value = serde_json::to_vec(&grants).map_err(|e| e.to_string())?;
    blind_set(&key, &value, owner)?;
    Ok(())
}

/// Check if a delegation grant exists for a specific resource+action.
fn check_delegation(owner: &str, subject: &str, resource: &str, action: &str) -> bool {
    let key = format!("{}:ucan:{}", owner, subject);
    if let Ok(Some(val)) = blind_get(&key, owner) {
        if let Ok(grants) = serde_json::from_slice::<Vec<DelegationGrant>>(&val) {
            let now = 0u64; // TODO: get current timestamp from host
            return grants.iter().any(|g| {
                g.resource == resource 
                && g.action == action 
                && (g.expires_at == 0 || g.expires_at > now)
            });
        }
    }
    false
}

// === Blind Persistence Helpers ===

fn blind_key(key: &str) -> String {
    let house_salt = persistence::get_house_salt();
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&house_salt).expect("HMAC error");
    mac.update(key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn get_encryption_key(user_id: &str) -> Result<chacha20poly1305::Key, String> {
    let hmac_secret = vault::get_hmac_secret(user_id);
    if hmac_secret.is_empty() { return Err("HMAC secret empty".to_string()); }
    let hk = Hkdf::<Sha256>::new(None, &hmac_secret);
    let mut enc_key_bytes = [0u8; 32];
    hk.expand(b"sovereign:blind-vault:encryption", &mut enc_key_bytes).map_err(|_| "HKDF failed")?;
    Ok(*chacha20poly1305::Key::from_slice(&enc_key_bytes))
}

fn blind_set(key: &str, value: &[u8], user_id: &str) -> Result<(), String> {
    let enc_key = get_encryption_key(user_id)?;
    let cipher = XChaCha20Poly1305::new(&enc_key);
    
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce error: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, value).map_err(|_| "Encryption failed")?;

    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    persistence::set(&blind_key(key), &blob).map_err(|e| format!("Persistence error: {:?}", e))?;
    Ok(())
}

fn blind_get(key: &str, user_id: &str) -> Result<Option<Vec<u8>>, String> {
    blind_get_by_blind_key(&blind_key(key), user_id)
}

fn blind_get_by_blind_key(b_key: &str, user_id: &str) -> Result<Option<Vec<u8>>, String> {
    let blob = match persistence::get(b_key) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("Persistence error: {:?}", e)),
    };

    if blob.len() < 24 {
        return Err("Invalid blob".to_string());
    }

    let enc_key = get_encryption_key(user_id)?;
    let cipher = XChaCha20Poly1305::new(&enc_key);
    let nonce = XNonce::from_slice(&blob[0..24]);
    let ciphertext = &blob[24..];
    
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed")?;
    Ok(Some(plaintext))
}

export!(AclStore);
