//! Low-level symmetric encryption utilities.
//!
//! Provides XChaCha20Poly1305 encrypt/decrypt primitives used internally
//! by the vault for seed encryption and routing token encryption.
//!
//! NOTE: DIDComm v2 JWE functions have been removed in the hybrid pivot.
//! Inter-user E2E encryption is now handled by OpenMLS.

use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Encrypt a payload using XChaCha20Poly1305 with a derived key.
///
/// Used internally for vault seed encryption and JIT routing tokens.
/// NOT for inter-user messaging (that's OpenMLS now).
pub fn xchacha20_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce entropy error: {}", e))?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    // Pack: [Nonce(24) | Ciphertext(...)]
    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a payload encrypted with `xchacha20_encrypt`.
///
/// Expects format: [Nonce(24) | Ciphertext(...)]
pub fn xchacha20_decrypt(key: &[u8; 32], packed: &[u8]) -> Result<Vec<u8>, String> {
    if packed.len() < 24 {
        return Err("Ciphertext too short".to_string());
    }
    let nonce = XNonce::from_slice(&packed[..24]);
    let ciphertext = &packed[24..];

    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed (authenticity check failed)".to_string())
}

/// Derive a symmetric key from a shared secret using HKDF-SHA256.
pub fn hkdf_derive_key(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).map_err(|_| "HKDF expansion failed")?;
    Ok(key)
}

/// Convert an Ed25519 secret seed to an X25519 static secret.
///
/// The Ed25519 scalar is derived as SHA-512(seed)[0..32] with clamping.
/// Still needed for JIT routing token encryption.
pub fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let mut scalar_bytes: [u8; 32] = hash[0..32].try_into().unwrap();
    // Standard X25519/Ed25519 clamping
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    scalar_bytes
}

/// Convert an Ed25519 public key to an X25519 public key (birational map).
/// Still needed for JIT routing token encryption.
pub fn ed25519_pub_to_x25519(ed_pub_bytes: &[u8; 32]) -> Option<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pub_bytes);
    let edwards_point = compressed.decompress()?;
    let x25519_point = edwards_point.to_montgomery();
    Some(x25519_point.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Hello, Sovereign World!";

        let encrypted = xchacha20_encrypt(&key, plaintext).unwrap();
        let decrypted = xchacha20_decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let plaintext = b"secret data";

        let encrypted = xchacha20_encrypt(&key, plaintext).unwrap();
        let result = xchacha20_decrypt(&wrong_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_derive_key() {
        let ikm = [1u8; 32];
        let key1 = hkdf_derive_key(&ikm, b"context-a").unwrap();
        let key2 = hkdf_derive_key(&ikm, b"context-b").unwrap();
        assert_ne!(key1, key2);

        // Same inputs → same output
        let key3 = hkdf_derive_key(&ikm, b"context-a").unwrap();
        assert_eq!(key1, key3);
    }

    #[test]
    fn test_ed25519_to_x25519() {
        let identity = crate::did::create_did_twin();
        let x25519 = ed25519_pub_to_x25519(&identity.public_key);
        assert!(x25519.is_some());
        assert_eq!(x25519.unwrap().len(), 32);
    }
}
