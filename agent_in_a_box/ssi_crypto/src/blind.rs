//! Blind persistence key derivation helpers.
//!
//! Extracted from `ssi_vault` and `acl_store`. These are pure crypto
//! operations decoupled from the WIT `persistence` interface.
//!
//! The actual storage read/write remains in the Wasm components that
//! import the `persistence` interface. This module provides only the
//! key derivation, HMAC-based key blinding, and encrypt/decrypt ops.

use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use sha2::Sha256;

const BLIND_VAULT_CONTEXT: &[u8] = b"sovereign:blind-vault:encryption";

/// Derive a blind (HMAC-based) key from a plaintext key and a house salt.
///
/// This ensures the storage layer cannot derive the original key name.
pub fn blind_key(key: &str, house_salt: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(house_salt).expect("HMAC key init failed");
    mac.update(key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Derive an encryption key from a master seed for blind-vault encryption.
pub fn derive_blind_encryption_key(master_seed: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut enc_key_bytes = [0u8; 32];
    hk.expand(BLIND_VAULT_CONTEXT, &mut enc_key_bytes)
        .map_err(|_| "HKDF failed for blind encryption key".to_string())?;
    Ok(enc_key_bytes)
}

/// Encrypt data for blind storage (XChaCha20Poly1305).
///
/// # Returns
/// A blob: `[Nonce(24) | Ciphertext(...)]`
pub fn blind_encrypt(value: &[u8], enc_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let key = chacha20poly1305::Key::from_slice(enc_key);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce entropy error: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, value)
        .map_err(|_| "Blind encryption failed".to_string())?;

    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt data from blind storage (XChaCha20Poly1305).
///
/// # Arguments
/// * `blob` - The stored blob: `[Nonce(24) | Ciphertext(...)]`
/// * `enc_key` - The 32-byte encryption key derived from `derive_blind_encryption_key`
pub fn blind_decrypt(blob: &[u8], enc_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if blob.len() < 24 {
        return Err("Invalid blind blob size (< 24 bytes)".to_string());
    }

    let key = chacha20poly1305::Key::from_slice(enc_key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&blob[0..24]);
    let ciphertext = &blob[24..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Blind decryption failed".to_string())
}

/// Derive the HMAC secret from a master seed (used for subject obfuscation).
pub fn derive_hmac_secret(master_seed: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut derived = [0u8; 32];
    hk.expand(b"sovereign:hmac-secret", &mut derived)
        .map_err(|_| "HKDF failed for HMAC secret".to_string())?;
    Ok(derived)
}

/// Derive the NATS Link NKey public key from a master seed.
pub fn derive_link_nkey_pubkey(master_seed: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut derived = [0u8; 32];
    hk.expand(b"sovereign:link-nkey", &mut derived)
        .map_err(|_| "HKDF failed for Link NKey".to_string())?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived);
    let public_key = signing_key.verifying_key();
    Ok(public_key.to_bytes())
}

/// Compute a node ID from a house salt.
pub fn compute_node_id(house_salt: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(house_salt).expect("HMAC key init failed");
    mac.update(b"sovereign-node-id");
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_key_deterministic() {
        let salt = [1u8; 32];
        let k1 = blind_key("test:key", &salt);
        let k2 = blind_key("test:key", &salt);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_blind_key_different_keys() {
        let salt = [1u8; 32];
        let k1 = blind_key("key_a", &salt);
        let k2 = blind_key("key_b", &salt);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_blind_encrypt_decrypt_roundtrip() {
        let seed = [42u8; 32];
        let enc_key = derive_blind_encryption_key(&seed).unwrap();

        let plaintext = b"sensitive vault data";
        let blob = blind_encrypt(plaintext, &enc_key).unwrap();
        let decrypted = blind_decrypt(&blob, &enc_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_blind_decrypt_wrong_key_fails() {
        let seed1 = [42u8; 32];
        let seed2 = [99u8; 32];
        let enc_key1 = derive_blind_encryption_key(&seed1).unwrap();
        let enc_key2 = derive_blind_encryption_key(&seed2).unwrap();

        let blob = blind_encrypt(b"secret", &enc_key1).unwrap();
        let result = blind_decrypt(&blob, &enc_key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_hmac_secret_deterministic() {
        let seed = [7u8; 32];
        let s1 = derive_hmac_secret(&seed).unwrap();
        let s2 = derive_hmac_secret(&seed).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_compute_node_id_deterministic() {
        let salt = [3u8; 32];
        let id1 = compute_node_id(&salt);
        let id2 = compute_node_id(&salt);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // hex-encoded SHA256
    }
}
