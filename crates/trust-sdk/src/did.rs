use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidError {
    #[error("Invalid DID format: {0}")]
    InvalidDidFormat(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid DID URL: {0}")]
    InvalidUrl(String),
    #[error("Path traversal detected")]
    PathTraversal,
    #[error("Port injection detected")]
    PortInjection,
    #[error("IP literal forbidden: {0}")]
    IpLiteralForbidden(String),
    #[error("Localhost forbidden: {0}")]
    LocalhostForbidden(String),
    #[error("Unsupported verification key type: {0}")]
    UnsupportedKeyType(String),
    #[error("Missing verification key")]
    MissingKey,
}

#[derive(Debug, Clone)]
pub struct DidIdentity {
    pub did: String,
    pub signing_seed: [u8; 32],
    pub public_key: [u8; 32],
}

pub fn create_did_twin_from_seed(seed_bytes: [u8; 32]) -> DidIdentity {
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let public_key = signing_key.verifying_key();
    let pub_hex = hex::encode(public_key.to_bytes());
    let did = format!("did:twin:z{pub_hex}");

    DidIdentity {
        did,
        signing_seed: seed_bytes,
        public_key: public_key.to_bytes(),
    }
}

pub fn extract_did_twin_ed25519_pubkey(did: &str) -> Result<[u8; 32], DidError> {
    let clean = did.split('#').next().unwrap_or(did);
    let hex_part = if let Some(stripped) = clean.strip_prefix("did:twin:z") {
        stripped
    } else if let Some(stripped) = clean.strip_prefix("did:twin:") {
        stripped
    } else {
        return Err(DidError::InvalidDidFormat(format!(
            "Expected 'did:twin:' or 'did:twin:z' prefix, got '{did}'"
        )));
    };

    let bytes = hex::decode(hex_part).map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(DidError::InvalidDidFormat(format!(
            "DID public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(key_bytes)
}

/// Create a W3C did:key identifier from a 32-byte Ed25519 signing seed.
pub fn create_did_key_from_seed(seed_bytes: [u8; 32]) -> DidIdentity {
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let public_key = signing_key.verifying_key().to_bytes();

    // Multicodec for ed25519-pub is 0xed01 (bytes: [0xed, 0x01])
    let mut multicodec_bytes = Vec::with_capacity(34);
    multicodec_bytes.push(0xed);
    multicodec_bytes.push(0x01);
    multicodec_bytes.extend_from_slice(&public_key);

    let b58 = bs58::encode(multicodec_bytes).into_string();
    let did = format!("did:key:z{b58}");

    DidIdentity {
        did,
        signing_seed: seed_bytes,
        public_key,
    }
}

/// Extract 32-byte Ed25519 public key from a W3C did:key identifier.
pub fn extract_did_key_ed25519_pubkey(did: &str) -> Result<[u8; 32], DidError> {
    let clean = did.split('#').next().unwrap_or(did).trim();
    let b58_part = if let Some(stripped) = clean.strip_prefix("did:key:z") {
        stripped
    } else {
        return Err(DidError::InvalidDidFormat(format!(
            "Expected 'did:key:z' prefix, got '{did}'"
        )));
    };

    let bytes = bs58::decode(b58_part)
        .into_vec()
        .map_err(|e| DidError::InvalidDidFormat(format!("Base58 decode error in '{did}': {e}")))?;

    if bytes.len() != 34 {
        return Err(DidError::InvalidDidFormat(format!(
            "Expected 34 multicodec bytes for Ed25519 did:key, got {}",
            bytes.len()
        )));
    }

    if bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(DidError::InvalidDidFormat(format!(
            "Invalid multicodec prefix for Ed25519: expected [0xed, 0x01], got [0x{:02x}, 0x{:02x}]",
            bytes[0], bytes[1]
        )));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bytes[2..34]);
    Ok(pubkey)
}

pub fn extract_public_key_from_twin_did(did: &str) -> Result<VerifyingKey, DidError> {
    let bytes = extract_did_twin_ed25519_pubkey(did)?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| DidError::InvalidDidFormat(e.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidDocument {
    pub id: String,
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "assertionMethod"
    )]
    pub assertion_method: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "publicKeyMultibase"
    )]
    pub public_key_multibase: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "publicKeyJwk"
    )]
    pub public_key_jwk: Option<serde_json::Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "publicKeyHex"
    )]
    pub public_key_hex: Option<String>,
}

impl VerificationMethod {
    pub fn extract_ed25519_pubkey(&self) -> Result<[u8; 32], DidError> {
        if let Some(ref hex_str) = self.public_key_hex {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(arr);
            }
        }

        if let Some(ref mb) = self.public_key_multibase {
            if let Some(stripped) = mb.strip_prefix('z') {
                let bytes = bs58::decode(stripped)
                    .into_vec()
                    .map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;
                // If multicodec 0xed01 prefix (2 bytes) + 32 bytes = 34 bytes
                if bytes.len() == 34 && bytes[0] == 0xed && bytes[1] == 0x01 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[2..34]);
                    return Ok(arr);
                } else if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Ok(arr);
                }
            }
        }

        if let Some(ref jwk) = self.public_key_jwk {
            let kty = jwk.get("kty").and_then(|v| v.as_str());
            let crv = jwk.get("crv").and_then(|v| v.as_str());
            if kty == Some("OKP") && (crv == Some("Ed25519") || crv.is_none()) {
                if let Some(x_str) = jwk.get("x").and_then(|v| v.as_str()) {
                    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(x_str)
                        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(x_str))
                        .map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        return Ok(arr);
                    }
                }
            }
        }

        Err(DidError::MissingKey)
    }
}

impl DidDocument {
    pub fn find_ed25519_pubkey(&self) -> Result<[u8; 32], DidError> {
        for vm in &self.verification_method {
            if let Ok(key) = vm.extract_ed25519_pubkey() {
                return Ok(key);
            }
        }
        Err(DidError::MissingKey)
    }
}

/// Convert did:web identifier to HTTPS URL.
/// Example:
/// - did:web:example.com -> https://example.com/.well-known/did.json
/// - did:web:example.com:agents:alpha -> https://example.com/agents/alpha/did.json
pub fn did_web_to_https_url(did: &str) -> Result<String, DidError> {
    did_web_to_https_url_with_options(did, false)
}

pub fn did_web_to_https_url_with_options(
    did: &str,
    allow_localhost: bool,
) -> Result<String, DidError> {
    let prefix = "did:web:";
    if !did.starts_with(prefix) {
        return Err(DidError::InvalidDidFormat(format!(
            "Expected 'did:web:' prefix, got '{did}'"
        )));
    }

    let remainder = &did[prefix.len()..];
    if remainder.is_empty() {
        return Err(DidError::InvalidDidFormat(
            "DID web body cannot be empty".to_string(),
        ));
    }

    let parts: Vec<&str> = remainder.split(':').collect();
    let domain = parts[0];

    // Check for percent-encoded port injection (%3a or %3A)
    if domain.to_lowercase().contains("%3a") {
        return Err(DidError::PortInjection);
    }

    // Check for explicit port injection in second segment
    if parts.len() > 1 && parts[1].chars().all(|c| c.is_ascii_digit()) {
        return Err(DidError::PortInjection);
    }

    // Check for IP literals
    let is_ipv4 = {
        let octets: Vec<&str> = domain.split('.').collect();
        octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
    };
    if is_ipv4 || domain.starts_with('[') || domain.contains("::") {
        return Err(DidError::IpLiteralForbidden(domain.to_string()));
    }

    // Check for localhost
    if (domain.eq_ignore_ascii_case("localhost") || domain.ends_with(".localhost"))
        && !allow_localhost
    {
        return Err(DidError::LocalhostForbidden(domain.to_string()));
    }

    // Check path parts
    let path_parts = &parts[1..];
    for part in path_parts {
        if part.is_empty() {
            return Err(DidError::InvalidUrl("Empty path segment".to_string()));
        }
        if *part == ".."
            || part.contains("/..")
            || part.contains("../")
            || part.to_lowercase().contains("%2e%2e")
        {
            return Err(DidError::PathTraversal);
        }
        if part.contains('/') || part.contains('\\') {
            return Err(DidError::InvalidUrl(
                "Invalid path separator in segment".to_string(),
            ));
        }
    }

    if path_parts.is_empty() {
        Ok(format!("https://{domain}/.well-known/did.json"))
    } else {
        let joined_path = path_parts.join("/");
        Ok(format!("https://{domain}/{joined_path}/did.json"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsEnvelope {
    pub payload: String,
    pub signature: String,
    pub kid: String,
}

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

pub fn verify_signed(jws_json: &str) -> Result<String, DidError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let env: JwsEnvelope =
        serde_json::from_str(jws_json).map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;

    let did = env.kid.split('#').next().unwrap_or(&env.kid);
    let verifying_key = extract_public_key_from_twin_did(did)?;

    let payload_bytes = b64
        .decode(&env.payload)
        .map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;
    let sig_bytes = b64
        .decode(&env.signature)
        .map_err(|e| DidError::InvalidDidFormat(e.to_string()))?;

    if sig_bytes.len() != 64 {
        return Err(DidError::SignatureError(
            "Signature must be 64 bytes".to_string(),
        ));
    }

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| DidError::SignatureError(e.to_string()))?;

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| DidError::VerificationFailed)?;

    String::from_utf8(payload_bytes).map_err(|e| DidError::InvalidDidFormat(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_creation_and_jws_sign_verify() {
        let seed = [42u8; 32];
        let identity = create_did_twin_from_seed(seed);
        assert!(identity.did.starts_with("did:twin:z"));

        let payload = r#"{"hello":"world"}"#;
        let jws = pack_signed(&identity.did, &identity.signing_seed, payload);

        let verified = verify_signed(&jws).expect("verification should succeed");
        assert_eq!(verified, payload);

        // Tamper with payload in JWS
        let mut parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        parsed["payload"] = serde_json::Value::String("dGFtcGVyZWQ".to_string());
        assert!(verify_signed(&parsed.to_string()).is_err());
    }

    #[test]
    fn test_did_twin_key_extraction() {
        let seed = [12u8; 32];
        let identity = create_did_twin_from_seed(seed);
        let extracted = extract_did_twin_ed25519_pubkey(&identity.did).unwrap();
        assert_eq!(extracted, identity.public_key);

        // With fragment
        let with_frag = format!("{}#key-1", identity.did);
        let extracted2 = extract_did_twin_ed25519_pubkey(&with_frag).unwrap();
        assert_eq!(extracted2, identity.public_key);
    }

    #[test]
    fn test_did_web_to_https_url() {
        let u1 = did_web_to_https_url("did:web:example.com").unwrap();
        assert_eq!(u1, "https://example.com/.well-known/did.json");

        let u2 = did_web_to_https_url("did:web:example.com:agents:alpha").unwrap();
        assert_eq!(u2, "https://example.com/agents/alpha/did.json");

        // Path traversal rejection
        assert_eq!(
            did_web_to_https_url("did:web:example.com:..:etc").unwrap_err(),
            DidError::PathTraversal
        );
        assert_eq!(
            did_web_to_https_url("did:web:example.com:%2e%2e:etc").unwrap_err(),
            DidError::PathTraversal
        );

        // Localhost rejection
        assert!(matches!(
            did_web_to_https_url("did:web:localhost"),
            Err(DidError::LocalhostForbidden(_))
        ));

        // IP literal rejection
        assert!(matches!(
            did_web_to_https_url("did:web:127.0.0.1"),
            Err(DidError::IpLiteralForbidden(_))
        ));
        assert!(matches!(
            did_web_to_https_url("did:web:192.168.1.1:tools:my_tool"),
            Err(DidError::IpLiteralForbidden(_))
        ));

        // Port injection rejection
        assert_eq!(
            did_web_to_https_url("did:web:example.com:8080").unwrap_err(),
            DidError::PortInjection
        );
        assert_eq!(
            did_web_to_https_url("did:web:example.com%3a8080").unwrap_err(),
            DidError::PortInjection
        );
    }

    #[test]
    fn test_did_document_key_extraction() {
        let pubkey_bytes = [7u8; 32];
        let pubkey_hex = hex::encode(pubkey_bytes);

        let doc = DidDocument {
            id: "did:web:example.com".to_string(),
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#key-1".to_string(),
                key_type: "Ed25519VerificationKey2020".to_string(),
                controller: "did:web:example.com".to_string(),
                public_key_multibase: None,
                public_key_jwk: None,
                public_key_hex: Some(pubkey_hex),
            }],
            authentication: None,
            assertion_method: None,
        };

        let found = doc.find_ed25519_pubkey().unwrap();
        assert_eq!(found, pubkey_bytes);
    }

    #[test]
    fn test_did_key_roundtrip_and_validation() {
        let seed = [99u8; 32];
        let identity = create_did_key_from_seed(seed);
        assert!(identity.did.starts_with("did:key:z"));

        let extracted = extract_did_key_ed25519_pubkey(&identity.did).unwrap();
        assert_eq!(extracted, identity.public_key);

        // Negative test: invalid prefix
        assert!(extract_did_key_ed25519_pubkey("did:key:not_a_z_key").is_err());
        assert!(extract_did_key_ed25519_pubkey("did:twin:1234").is_err());
    }
}
