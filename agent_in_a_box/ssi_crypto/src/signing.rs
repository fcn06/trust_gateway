//! Ed25519 signing and JWS verification.
//!
//! Extracted from `ssi_vault::pack_signed` / `verify_signed`.
//! Pure functions operating on key material — no persistence dependency.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use base64::Engine;

/// A JWS (JSON Web Signature) envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwsEnvelope {
    /// Base64url-encoded payload
    pub payload: String,
    /// Base64url-encoded Ed25519 signature
    pub signature: String,
    /// Key ID in the form `did:twin:z<hex>#key-1`
    pub kid: String,
}

/// Sign a payload with an Ed25519 key and produce a JWS envelope.
///
/// # Arguments
/// * `sender_did` - The signer's DID (used in the `kid` field)
/// * `signing_seed` - The 32-byte Ed25519 seed
/// * `payload` - The plaintext payload to sign
///
/// # Returns
/// A JSON string containing the JWS envelope.
pub fn pack_signed(sender_did: &str, signing_seed: &[u8; 32], payload: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signing_key = SigningKey::from_bytes(signing_seed);
    let payload_bytes = payload.as_bytes();
    let signature = signing_key.sign(payload_bytes);

    let envelope = serde_json::json!({
        "payload": b64.encode(payload_bytes),
        "signature": b64.encode(signature.to_bytes()),
        "kid": format!("{}#key-1", sender_did)
    });

    envelope.to_string()
}

/// Sign raw bytes with an Ed25519 key.
///
/// # Arguments
/// * `signing_seed` - The 32-byte Ed25519 seed
/// * `message` - The bytes to sign
///
/// # Returns
/// The 64-byte Ed25519 signature.
pub fn sign_bytes(signing_seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(signing_seed);
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify a JWS envelope and return the decoded payload if valid.
///
/// Extracts the public key from the `kid` field (expecting `did:twin:z<hex>#key-1`),
/// verifies the Ed25519 signature, and returns the plaintext payload.
///
/// # Arguments
/// * `envelope_json` - The JWS envelope JSON string
///
/// # Returns
/// The decoded payload string, or an empty string if verification fails.
pub fn verify_signed(envelope_json: &str) -> Result<String, String> {
    let envelope: serde_json::Value =
        serde_json::from_str(envelope_json).map_err(|_| "Invalid JSON".to_string())?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let payload_b64 = envelope["payload"]
        .as_str()
        .ok_or("Missing payload")?;
    let signature_b64 = envelope["signature"]
        .as_str()
        .ok_or("Missing signature")?;
    let kid = envelope["kid"]
        .as_str()
        .ok_or("Missing kid")?;

    // Extract DID from kid
    let did = kid.split('#').next().ok_or("Invalid kid format")?;
    if did.len() < 11 || !did.starts_with("did:twin:z") {
        return Err("Invalid DID format in kid".to_string());
    }

    let hex_part = &did[10..];
    let pub_key_bytes = hex::decode(hex_part).map_err(|_| "Invalid hex in DID")?;
    let pub_key_arr: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid public key length")?;

    let pub_key =
        VerifyingKey::from_bytes(&pub_key_arr).map_err(|_| "Invalid Ed25519 public key")?;

    let payload_bytes = b64
        .decode(payload_b64)
        .map_err(|_| "Invalid payload encoding")?;
    let signature_bytes = b64
        .decode(signature_b64)
        .map_err(|_| "Invalid signature encoding")?;

    let sig_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid signature length")?;
    let signature = Signature::from_bytes(&sig_arr);

    pub_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| "Signature verification failed")?;

    String::from_utf8(payload_bytes).map_err(|_| "Invalid UTF-8 in payload".to_string())
}

/// Verify an Ed25519 signature against a public key and message.
pub fn verify_bytes(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::create_did_twin;

    #[test]
    fn test_sign_verify_roundtrip() {
        let identity = create_did_twin();
        let payload = "Hello, Sovereign Identity!";

        let envelope_json = pack_signed(&identity.did, &identity.signing_seed, payload);
        let verified = verify_signed(&envelope_json).unwrap();

        assert_eq!(verified, payload);
    }

    #[test]
    fn test_verify_tampered_payload_fails() {
        let identity = create_did_twin();
        let envelope_json = pack_signed(&identity.did, &identity.signing_seed, "original");

        // Tamper with the payload
        let mut envelope: serde_json::Value = serde_json::from_str(&envelope_json).unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        envelope["payload"] = serde_json::Value::String(b64.encode(b"tampered"));

        let result = verify_signed(&envelope.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_verify_bytes() {
        let identity = create_did_twin();
        let message = b"test message bytes";

        let sig = sign_bytes(&identity.signing_seed, message);
        assert!(verify_bytes(&identity.public_key, message, &sig));

        // Wrong message should fail
        assert!(!verify_bytes(&identity.public_key, b"wrong", &sig));
    }
}
