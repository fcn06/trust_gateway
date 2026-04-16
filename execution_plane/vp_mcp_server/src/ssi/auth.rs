//! SSI delegation authentication module.
//!
//! Provides verification of MCP calls using SSI delegation, including
//! signature verification, instruction binding, and VP validation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::types::PlainDidcomm;

/// Claims extracted from a verified session JWT.
#[derive(Debug, Clone)]
pub struct JwtClaims {
    /// The delegatee's DID (from JWT `kid` header).
    pub sender_did: String,
    /// The data-owner's DID (from `user_did` claim). This is the hard isolation boundary.
    pub user_did: String,
    /// Authorization clearance level: "standard" or "elevated".
    pub clearance_level: String,
    /// Scope array from the JWT claims.
    pub scope: Vec<String>,
}

/// Verify an MCP call using SSI delegation.
///
/// This function:
/// 1. Parses the signed envelope
/// 2. Extracts and validates the public key from the DID
/// 3. Verifies the cryptographic signature
/// 4. Verifies the instruction hash binding
/// 5. Validates the Verifiable Presentation
///
/// # Arguments
/// * `received_instruction` - The instruction text that was received
/// * `opaque_envelope` - The signed DIDComm envelope in JSON format
///
/// # Returns
/// * `Ok(String)` - The sender's DID if verification succeeds
/// * `Err(String)` - A description of why verification failed
pub async fn verify_mcp_call(
    received_instruction: &str,
    opaque_envelope: &str,
) -> std::result::Result<String, String> {
    // 1. Parse the signed envelope
    let envelope: serde_json::Value = serde_json::from_str(opaque_envelope)
        .map_err(|e| format!("Invalid signed envelope: {}", e))?;

    let payload_b64 = envelope
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing payload in signed message".to_string())?;
    let signature_b64 = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing signature in signed message".to_string())?;
    let kid = envelope
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing kid in signed message".to_string())?;

    tracing::info!("Verifying MCP call with kid: {}", kid);


    // 2. Extract Public Key
    let sender_did_str = kid
        .split('#')
        .next()
        .ok_or_else(|| "Invalid kid format".to_string())?;

    let pub_key_bytes = extract_public_key(sender_did_str)?;

    let verifying_key = VerifyingKey::from_bytes(
        pub_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid public key length".to_string())?,
    )
    .map_err(|e| format!("Invalid public key: {}", e))?;

    // 3. Verify Signature
    let payload_bytes = BASE64
        .decode(payload_b64)
        .map_err(|e| format!("Invalid payload encoding: {}", e))?;
    let signature_bytes = BASE64
        .decode(signature_b64)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;

    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())?,
    );

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| "Signature verification failed".to_string())?;

    // 4. Deserialize Payload
    let plain: PlainDidcomm = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Failed to deserialize payload: {}", e))?;

    // 5. Verify Instruction Binding
    let mut hasher = Sha256::new();
    hasher.update(received_instruction.as_bytes());
    let current_hash = hex::encode(hasher.finalize());

    let original_hash = plain
        .body
        .get("instruction_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing instruction_hash in DIDComm body".to_string())?;

    if current_hash != original_hash {
        return Err("Instruction tampering detected! Hash mismatch.".into());
    }

    // 6. Verify Verifiable Presentation (VP)
    let vp = plain
        .body
        .get("vp")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing vp in DIDComm body".to_string())?;

    validate_vp_signature(vp, sender_did_str).await?;

    Ok(sender_did_str.to_string())
}

/// Validate a Verifiable Presentation signature.
///
/// Currently a placeholder implementation that logs and accepts any VP.
async fn validate_vp_signature(vp: &str, sender_did: &str) -> std::result::Result<bool, String> {
    tracing::info!("Validating VP from {}: {}", sender_did, vp);
    Ok(true)
}

fn extract_public_key(sender_did_str: &str) -> std::result::Result<Vec<u8>, String> {
    if let Some(key_raw) = sender_did_str.strip_prefix("did:twin:") {
        if key_raw.starts_with('z') {
             if let Ok(decoded) = bs58::decode(key_raw).into_vec() {
                 if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
                     return Ok(decoded[2..].to_vec());
                 } else if decoded.len() == 32 {
                     return Ok(decoded);
                 } else {
                     return Err("Invalid Base58 key length".to_string());
                 }
             } else {
                if let Ok(decoded) = hex::decode(&key_raw[1..]) {
                    if decoded.len() == 32 {
                        tracing::warn!("Detected Hex encoded key with 'z' prefix. Accepting as legacy/quirk.");
                        return Ok(decoded);
                    } else {
                        return Err("Invalid Hex key length in did:twin".to_string());
                    }
                } else {
                    return Err("Invalid or unsupported key in did:twin Multibase (tried Base58 and Hex)".to_string());
                }
             }
        } else {
            return BASE64.decode(key_raw)
                .map_err(|e| format!("Invalid public key encoding in DID: {}", e));
        }
    } else if let Some(key_multibase) = sender_did_str.strip_prefix("did:key:z") {
        let decoded = bs58::decode(key_multibase).into_vec()
            .map_err(|e| format!("Invalid Base58 encoding: {}", e))?;
        if decoded.len() != 34 {
            return Err(format!("Invalid did:key length: {}. Expected 34 bytes for Ed25519", decoded.len()));
        }
        if decoded[0] != 0xed || decoded[1] != 0x01 {
             return Err("Unsupported key type (not Ed25519)".to_string());
        }
        return Ok(decoded[2..].to_vec());
    }
    Err(format!("Unsupported DID method: {}. Expected did:twin or did:key", sender_did_str))
}

/// Verifies a short-lived session JWT for an MCP tool call.
///
/// Returns the full `JwtClaims` (sender_did, user_did, clearance_level, scope)
/// if verification succeeds.
pub async fn verify_session_jwt(jwt: &str) -> std::result::Result<JwtClaims, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format (expected 3 parts)".to_string());
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_bytes = BASE64.decode(header_b64).map_err(|e| format!("Invalid header base64: {}", e))?;
    let claims_bytes = BASE64.decode(claims_b64).map_err(|e| format!("Invalid claims base64: {}", e))?;
    let signature_bytes = BASE64.decode(signature_b64).map_err(|e| format!("Invalid signature base64: {}", e))?;

    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| format!("Invalid header JSON: {}", e))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).map_err(|e| format!("Invalid claims JSON: {}", e))?;

    let kid = header.get("kid").and_then(|v| v.as_str()).ok_or_else(|| "Missing kid in JWT header".to_string())?;
    let sender_did_str = kid.split('#').next().ok_or_else(|| "Invalid kid format".to_string())?;

    let pub_key_bytes = extract_public_key(sender_did_str)?;

    let verifying_key = VerifyingKey::from_bytes(
        pub_key_bytes.as_slice().try_into().map_err(|_| "Invalid public key length".to_string())?
    ).map_err(|e| format!("Invalid public key: {}", e))?;

    let signature = Signature::from_bytes(
        signature_bytes.as_slice().try_into().map_err(|_| "Invalid signature length".to_string())?
    );

    let message_to_verify = format!("{}.{}", header_b64, claims_b64);
    verifying_key.verify(message_to_verify.as_bytes(), &signature)
        .map_err(|_| "JWT signature verification failed".to_string())?;

    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if now > exp {
            return Err("JWT has expired".to_string());
        }
    } else {
        return Err("Missing exp claim in JWT".to_string());
    }

    // Extract user_did (the data-owner DID)
    let user_did = claims.get("user_did")
        .and_then(|v| v.as_str())
        .unwrap_or(sender_did_str)
        .to_string();

    // Extract scope array
    let scope: Vec<String> = claims.get("scope")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    // Extract clearance_level from scope entries with "clearance:" prefix.
    // Falls back to "standard" if not found.
    let clearance_level = scope.iter()
        .find_map(|s| s.strip_prefix("clearance:").map(|v| v.to_string()))
        .unwrap_or_else(|| "standard".to_string());

    Ok(JwtClaims {
        sender_did: sender_did_str.to_string(),
        user_did,
        clearance_level,
        scope,
    })
}
