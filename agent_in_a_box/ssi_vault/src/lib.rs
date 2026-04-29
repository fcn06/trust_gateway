use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use base64::Engine;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2
};
use secrecy::{Secret, ExposeSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};

wit_bindgen::generate!({
    world: "ssi-vault",
    path: "../wit",
    additional_derives: [serde::Serialize, serde::Deserialize],
});

pub mod commands;
use commands::{UnlockVaultCommand, CreateIdentityCommand, VaultCommand, 
               jwt::{IssueSessionJwtCommand, VerifySessionJwtCommand}};

use exports::sovereign::gateway::vault::Guest;
use sovereign::gateway::persistence;

// Wrapper for the Master Seed to ensure it's zeroized on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MasterSeed(Vec<u8>);

// In-memory key store: Maps user_id -> Decrypted Master Seed
// This is the "Unlocked State". If a user is not in this map, they are "Locked".
lazy_static::lazy_static! {
    static ref UNLOCKED_USERS: Mutex<HashMap<String, MasterSeed>> = Mutex::new(HashMap::new());
    // Fallback store for when Vault is LOCKED (e.g. NATS data loss). 
    // Prevents panic in create_identity by storing seeds in memory for the session.
    static ref EPHEMERAL_SEEDS: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
}

struct SsiVault;

// KDF Info strings
const INFO_LINK_NKEY: &[u8] = b"sovereign:link-nkey";
const INFO_HMAC_SECRET: &[u8] = b"sovereign:hmac-secret";
const INFO_DID_DERIVATION: &[u8] = b"sovereign:did-derivation";

// Crypto Constants
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20Poly1305 nonce length

impl Guest for SsiVault {
    // === Blueprint Master Seed Functions ===

    fn generate_master_seed(user_id: String, derivation_path: String) -> Result<bool, String> {
        let key = format!("master_seed:{}", user_id);
        
        // 1. Check if seed already exists
        if matches!(persistence::get(&blind_key(&key)), Ok(Some(_))) {
            tracing::warn!("⚠️ Master Seed already exists for user: {}", user_id);
            return Ok(false);
        }
        
        // 2. Generate new random Master Seed (32 bytes)
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).map_err(|e| format!("Entropy error: {}", e))?;
        
        // 3. Prepare Encryption
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| format!("Salt entropy error: {}", e))?;
        
        let kek = derive_kek(&derivation_path, &salt)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce entropy error: {}", e))?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        // 4. Encrypt the Master Seed
        let cipher = XChaCha20Poly1305::new(&kek);
        let ciphertext = cipher.encrypt(nonce, seed_bytes.as_ref())
            .map_err(|_| "Encryption failed")?;

        // 5. Pack data: [Version(1) | Salt(16) | Nonce(24) | Ciphertext(...)]
        let mut storage_blob = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        storage_blob.push(0x02); // Version 2 (Authenticated Encrypted)
        storage_blob.extend_from_slice(&salt);
        storage_blob.extend_from_slice(&nonce_bytes);
        storage_blob.extend_from_slice(&ciphertext);
        
        // 6. Persist
        let b_key = blind_key(&key);
        persistence::set(&b_key, &storage_blob).map_err(|e| format!("Persistence error: {:?}", e))?;

        // 7. Derive and persist Routing Secret (HMAC) - Plaintext content (Host-accessible for routing)
        let hk = Hkdf::<Sha256>::new(None, &seed_bytes);
        let mut routing_secret = [0u8; 32];
        hk.expand(INFO_HMAC_SECRET, &mut routing_secret).map_err(|_| "HKDF failed")?;
        
        let hmac_key = format!("hmac_secret:{}", user_id);
        persistence::set(&blind_key(&hmac_key), &routing_secret.to_vec()).map_err(|e| format!("Persistence error: {:?}", e))?;
        
        // 8. Place in memory for current session (Unlock)
        {
            let mut map = UNLOCKED_USERS.lock().unwrap();
            map.insert(user_id.to_string(), MasterSeed(seed_bytes.to_vec()));
        }

        tracing::info!("🔐 Generated and Encrypted Master Seed for user: {}", user_id);
        Ok(true)
    }

    fn derive_link_nkey(user_id: String) -> Result<String, String> {
        let seed_guard = get_master_seed(&user_id)?;
        let seed = &seed_guard.0;
        
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut derived = [0u8; 32];
        hk.expand(INFO_LINK_NKEY, &mut derived)
            .map_err(|_| "HKDF expansion failed")?;
        
        let signing_key = SigningKey::from_bytes(&derived);
        let public_key = signing_key.verifying_key();
        
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.to_bytes());
        
        tracing::info!("🔑 Derived Link NKey for user: {} -> {}", user_id, &pub_b64[..16]);
        Ok(pub_b64)
    }

    fn unlock_vault(user_id: String, derivation_path: String) -> Result<bool, String> {
        UnlockVaultCommand { user_id, derivation_path }.execute()
    }

    fn is_unlocked(user_id: String) -> bool {
        let unlocks = UNLOCKED_USERS.lock().unwrap();
        unlocks.contains_key(&user_id)
    }

    fn get_hmac_secret(user_id: String) -> Vec<u8> {
        let seed_guard = match get_master_seed(&user_id) {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let seed = &seed_guard.0;
        
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut derived = [0u8; 32];
        if hk.expand(INFO_HMAC_SECRET, &mut derived).is_err() {
            return Vec::new();
        }
        
        derived.to_vec()
    }

    // === JIT Routing ===

    fn encrypt_routing_token(routing_key: String, target_id: String) -> Result<String, String> {
        use x25519_dalek::{StaticSecret, PublicKey};
        
        // 1. Decode Gateway Public Key (Base64)
        let gateway_pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(&routing_key)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&routing_key))
            .map_err(|e| format!("Invalid routing key Base64: {}", e))?;
            
        let gateway_pub_arr: [u8; 32] = gateway_pub_bytes.try_into()
            .map_err(|_| "Invalid routing key length".to_string())?;
        let gateway_public = PublicKey::from(gateway_pub_arr);

        // 2. Generate Ephemeral Sender Key
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // 3. ECDH Shared Secret
        let shared_secret = ephemeral_secret.diffie_hellman(&gateway_public);

        // 4. Derive Key and Nonce via HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"sovereign:jit-routing", &mut key_bytes).map_err(|_| "HKDF failed")?;
        let key = chacha20poly1305::Key::from_slice(&key_bytes);
        
        // 5. Encrypt Target ID
        let cipher = XChaCha20Poly1305::new(key);
        let mut nonce_bytes = [0u8; 24];
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce entropy error: {}", e))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, target_id.as_bytes())
            .map_err(|_| "Encryption failed")?;

        // 6. Pack: [Version(1) | EphemeralPub(32) | Nonce(24) | Ciphertext]
        let mut token_bytes = Vec::with_capacity(1 + 32 + 24 + ciphertext.len());
        token_bytes.push(0x01); // Version
        token_bytes.extend_from_slice(ephemeral_public.as_bytes());
        token_bytes.extend_from_slice(&nonce_bytes);
        token_bytes.extend_from_slice(&ciphertext);
        
        // 7. Return Base64 URL Safe
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes))
    }

    // === DID Management ===

    fn create_identity(user_id: String) -> Result<String, String> {
        CreateIdentityCommand { user_id, is_peer: false }.execute()
    }

    fn create_peer_identity(user_id: String) -> Result<String, String> {
        CreateIdentityCommand { user_id, is_peer: true }.execute()
    }

    fn sign_message(did: String, message: Vec<u8>) -> Result<Vec<u8>, String> {
        // Find owner of this DID to get their seed
        let blind_did_user = blind_key(&format!("did_user:{}", did));
        let user_id_bytes = match persistence::get(&blind_did_user) {
            Ok(Some(b)) => b,
            _ => {
                return Err(format!("DID owner not found for {}", did));
            }
        };
        let user_id = match String::from_utf8(user_id_bytes) {
            Ok(uid) => uid,
            Err(_) => {
                return Err(format!("Invalid user_id mapping for {}", did));
            }
        };

        let seed_bytes = match blind_get(&format!("seed:{}", did), &user_id) {
            Ok(Some(b)) => b,
            _ => {
                // Check ephemeral store
                let map = EPHEMERAL_SEEDS.lock().unwrap();
                if let Some(b) = map.get(&did) {
                    b.clone()
                } else {
                    return Err(format!("Seed not found for {}", did));
                }
            },
        };
        let seed: [u8; 32] = match seed_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return Err("Invalid seed length".to_string()),
        };
        
        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(&message);
        Ok(signature.to_bytes().to_vec())
    }

    fn get_active_did(user_id: String) -> Result<String, String> {
        match blind_get(&format!("active_did:{}", user_id), &user_id) {
            Ok(Some(did_bytes)) => Ok(String::from_utf8(did_bytes).unwrap_or_default()),
            Ok(None) => Ok(String::new()),
            Err(e) => Err(e),
        }
    }

    fn set_active_did(user_id: String, did: String) -> Result<bool, String> {
        let dids: Vec<String> = if let Some(val) = blind_get(&format!("user_dids:{}", user_id), &user_id)? {
            serde_json::from_slice(&val).unwrap_or_default()
        } else {
            return Err("User has no DIDs".to_string());
        };
        
        if !dids.contains(&did) {
            return Err("DID does not belong to user".to_string());
        }

        blind_set(&format!("active_did:{}", user_id), did.as_bytes(), &user_id)?;
        Ok(true)
    }

    fn list_identities(user_id: String) -> Result<Vec<String>, String> {
        match blind_get(&format!("user_dids:{}", user_id), &user_id) {
            Ok(Some(val)) => Ok(serde_json::from_slice(&val).unwrap_or_default()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn resolve_did_to_user_id(did: String) -> Result<String, String> {
        let b_key = blind_key(&format!("did_user:{}", did));
        match persistence::get(&b_key) {
            Ok(Some(bytes)) => Ok(String::from_utf8(bytes).unwrap_or_default()),
            Ok(None) => Ok(String::new()),
            Err(e) => Err(format!("Persistence error: {:?}", e)),
        }
    }

    // === Agent Delegation (V5) ===
    
    fn issue_session_jwt(subject: String, scope: Vec<String>, user_did: String, ttl_seconds: u32, tenant_id: String) -> Result<String, String> {
        IssueSessionJwtCommand { subject, scope, user_did, ttl_seconds, tenant_id }.execute()
    }

    fn verify_session_jwt(jwt: String) -> Result<String, String> {
        VerifySessionJwtCommand { jwt }.execute()
    }

    // === Connection Model (V6) ===

    fn create_service_did(tenant_id: String) -> Result<String, String> {
        let identity = ssi_crypto::did::create_service_did(&tenant_id);

        // Store the service DID seed in the system-accessible area (not user-locked)
        let seed_key = format!("service_did_seed:{}", identity.did);
        persistence::set(&blind_key(&seed_key), &identity.signing_seed.to_vec()).map_err(|e| format!("Persistence error: {:?}", e))?;

        // Map DID -> tenant_id
        let did_tenant_key = format!("did_tenant:{}", identity.did);
        persistence::set(&blind_key(&did_tenant_key), tenant_id.as_bytes()).map_err(|e| format!("Persistence error: {:?}", e))?;

        tracing::info!("✅ Created Service DID for tenant {}: {}", tenant_id, identity.did);
        Ok(identity.did)
    }

    // === NEW: DID Document Generation (Hybrid Architecture) ===

    fn create_did_document(user_id: String, gateway_url: String, target_id: String) -> Result<String, String> {
        // 1. Get user's active DID
        let did = Self::get_active_did(user_id.clone())?;
        if did.is_empty() {
            return Err("No active DID for user".to_string());
        }

        // 2. Extract public key hex from DID (did:twin:z<hex>)
        let pub_key_hex = ssi_crypto::did::parse_did_twin_pubkey(&did)
            .map(|bytes| hex::encode(bytes))
            .ok_or_else(|| "Failed to parse public key from DID".to_string())?;

        // 3. Build the DID Document
        let doc = ssi_crypto::did_document::build_did_document(
            &did,
            &pub_key_hex,
            &gateway_url,
            &target_id,
        );

        // 4. Serialize to JSON
        ssi_crypto::did_document::serialize_did_document(&doc)
    }
}

// === Connection Model (V6): Delegation Interface Implementation ===

use exports::sovereign::gateway::delegation::Guest as DelegationGuest;

impl DelegationGuest for SsiVault {
    fn validate_ucan(
        token: String,
        required_resource: String,
        required_action: String,
    ) -> Result<String, String> {
        let ucan = ssi_crypto::ucan::decode_ucan(&token)?;
        let cap = ssi_crypto::ucan::Capability {
            resource: required_resource,
            action: required_action,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match ssi_crypto::ucan::validate_ucan(&ucan, &cap, now) {
            ssi_crypto::ucan::UcanValidationResult::Authorized => Ok("authorized".to_string()),
            ssi_crypto::ucan::UcanValidationResult::RequiresApproval => {
                Ok("requires_approval".to_string())
            }
            ssi_crypto::ucan::UcanValidationResult::Denied(reason) => Err(reason),
        }
    }

    fn create_action_request(
        tool_name: String,
        args_hash: String,
        summary: String,
    ) -> exports::sovereign::gateway::delegation::ActionRequest {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let req = ssi_crypto::ucan::create_action_request(&tool_name, &args_hash, &summary, 300, now);

        exports::sovereign::gateway::delegation::ActionRequest {
            request_id: req.request_id,
            tool_name: req.tool_name,
            human_summary: req.human_summary,
            payload_hash: req.payload_hash,
            expires_at: req.expires_at,
        }
    }

    fn verify_action_response(
        response: exports::sovereign::gateway::delegation::ActionResponse,
        expected_hash: String,
        user_pubkey: Vec<u8>,
    ) -> Result<bool, String> {
        let crypto_response = ssi_crypto::ucan::ActionResponse {
            request_id: response.request_id,
            approved: response.approved,
            signature: response.signature,
        };

        if user_pubkey.len() != 32 {
            return Err(format!("Invalid public key length: {} bytes", user_pubkey.len()));
        }
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&user_pubkey);

        ssi_crypto::ucan::verify_action_response(&crypto_response, &expected_hash, &pubkey_arr)
    }
}

pub(crate) fn compute_node_id() -> String {
    let house_salt = persistence::get_house_salt();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&house_salt).expect("HMAC error");
    mac.update(b"sovereign-node-id");
    hex::encode(mac.finalize().into_bytes())
}

// === Blind Persistence Helpers ===

fn blind_key(key: &str) -> String {
    let house_salt = persistence::get_house_salt();
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&house_salt).expect("HMAC error");
    mac.update(key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn blind_set(key: &str, value: &[u8], user_id: &str) -> Result<(), String> {
    let seed_guard = get_master_seed(user_id)?;
    let seed = &seed_guard.0;
    
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut enc_key_bytes = [0u8; 32];
    hk.expand(b"sovereign:blind-vault:encryption", &mut enc_key_bytes).map_err(|_| "HKDF failed")?;
    let enc_key = chacha20poly1305::Key::from_slice(&enc_key_bytes);

    let cipher = XChaCha20Poly1305::new(enc_key);
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce entropy error: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, value).map_err(|_| "Encryption failed")?;

    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    persistence::set(&blind_key(key), &blob).map_err(|e| format!("Persistence error: {:?}", e))?;
    
    Ok(())
}

fn blind_get(key: &str, user_id: &str) -> Result<Option<Vec<u8>>, String> {
    let b_key = blind_key(key);
    
    let blob = match persistence::get(&b_key) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("Persistence error: {:?}", e)),
    };

    if blob.len() < 24 {
        return Err("Invalid blind blob size".to_string());
    }

    let seed_guard = get_master_seed(user_id)?;
    let seed = &seed_guard.0;
    
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut enc_key_bytes = [0u8; 32];
    hk.expand(b"sovereign:blind-vault:encryption", &mut enc_key_bytes).map_err(|_| "HKDF failed")?;
    let enc_key = chacha20poly1305::Key::from_slice(&enc_key_bytes);

    let nonce = XNonce::from_slice(&blob[0..24]);
    let ciphertext = &blob[24..];
    let cipher = XChaCha20Poly1305::new(enc_key);
    
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed")?;

    Ok(Some(plaintext))
}

// === Helper Functions ===

fn derive_kek(password: &str, salt: &[u8]) -> Result<chacha20poly1305::Key, String> {
    let mut kek = [0u8; 32];
    let params = argon2::Params::default();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    
    argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut kek
    ).map_err(|e| format!("Argon2 derivation failed: {}", e))?;
    
    Ok(*chacha20poly1305::Key::from_slice(&kek))
}

fn get_master_seed(user_id: &str) -> Result<MasterSeed, String> {
    let unlocks = UNLOCKED_USERS.lock().unwrap();
    if let Some(seed) = unlocks.get(user_id) {
        Ok(seed.clone())
    } else {
        Err("Vault is LOCKED. User must authenticate to unlock.".to_string())
    }
}

fn count_user_dids(user_id: &str) -> u32 {
    if let Some(val) = blind_get(&format!("user_dids:{}", user_id), user_id).unwrap_or_default() {
        let dids: Vec<String> = serde_json::from_slice(&val).unwrap_or_default();
        dids.len() as u32
    } else {
        0
    }
}

fn derive_did_key(master_seed: &[u8], index: u32) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let info = format!("{}:{}", String::from_utf8_lossy(INFO_DID_DERIVATION), index);
    let mut derived = [0u8; 32];
    hk.expand(info.as_bytes(), &mut derived).expect("HKDF expansion failed");
    SigningKey::from_bytes(&derived)
}

export!(SsiVault);
