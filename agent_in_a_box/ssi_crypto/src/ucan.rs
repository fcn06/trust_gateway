//! UCAN (User Controlled Authorization Networks) types and validation.
//!
//! Core UCAN data structures for the Connection Model:
//! - `UcanToken` — a capability delegation token
//! - `Capability` — a resource + action pair
//! - `ActionRequest` / `ActionResponse` — the cryptographic leash exchange
//!
//! This is a minimal subset of the UCAN spec sufficient for B2B delegation.

use serde::{Deserialize, Serialize};

/// A single capability (resource + action) that can be delegated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// The resource being accessed (e.g., "messaging", "calendar", "payment")
    pub resource: String,
    /// The action permitted (e.g., "send", "read", "execute")
    pub action: String,
}

/// A UCAN delegation token.
///
/// Represents a user granting specific capabilities to a B2B agent.
/// The user's wallet mints these tokens during the connection onboarding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcanToken {
    /// The DID of the entity granting the capabilities (user's pairwise DID)
    pub issuer: String,
    /// The DID of the entity receiving the capabilities (B2B service DID)
    pub audience: String,
    /// The specific capabilities being delegated
    pub capabilities: Vec<Capability>,
    /// Expiry timestamp (Unix epoch seconds). 0 = no expiry.
    pub expiry: u64,
    /// Chain of proof tokens (for delegation chains). Empty for root grants.
    pub proof_chain: Vec<String>,
    /// Unique token identifier
    pub token_id: String,
}

/// An action request sent from the B2B agent to the user's wallet
/// when a tool requires explicit user approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Unique request identifier
    pub request_id: String,
    /// The MCP tool that requires approval (e.g., "process_refund")
    pub tool_name: String,
    /// Human-readable summary (e.g., "Approve $42 refund")
    pub human_summary: String,
    /// SHA-256 hash of the exact tool arguments
    pub payload_hash: String,
    /// Expiry timestamp (Unix epoch seconds)
    pub expires_at: u64,
}

/// An action response returned from the user's wallet after approval/rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    /// Must match the `request_id` from the corresponding `ActionRequest`
    pub request_id: String,
    /// Whether the user approved the action
    pub approved: bool,
    /// Ed25519 signature of the `payload_hash` (present only if approved)
    pub signature: Option<Vec<u8>>,
}

/// Result of UCAN validation.
#[derive(Debug, Clone)]
pub enum UcanValidationResult {
    /// The UCAN grants the required capability
    Authorized,
    /// The UCAN does not grant the required capability — needs wallet approval
    RequiresApproval,
    /// The UCAN is expired or otherwise invalid
    Denied(String),
}

/// Encode a UCAN token to a JSON string.
pub fn encode_ucan(token: &UcanToken) -> Result<String, String> {
    serde_json::to_string(token).map_err(|e| format!("UCAN encoding failed: {}", e))
}

/// Decode a UCAN token from a JSON string.
pub fn decode_ucan(json: &str) -> Result<UcanToken, String> {
    serde_json::from_str(json).map_err(|e| format!("UCAN decoding failed: {}", e))
}

/// Validate whether a UCAN token grants a specific capability.
///
/// # Arguments
/// * `token` - The UCAN token to validate
/// * `required_cap` - The capability needed for the current operation
/// * `now_epoch` - Current Unix timestamp for expiry checking
///
/// # Returns
/// `UcanValidationResult` indicating whether the capability is authorized,
/// requires wallet approval, or is denied.
pub fn validate_ucan(
    token: &UcanToken,
    required_cap: &Capability,
    now_epoch: u64,
) -> UcanValidationResult {
    // 1. Check expiry
    if token.expiry > 0 && now_epoch > token.expiry {
        return UcanValidationResult::Denied("UCAN token expired".to_string());
    }

    // 2. Check if the required capability is in the token's capability list
    for cap in &token.capabilities {
        if capability_satisfies(cap, required_cap) {
            return UcanValidationResult::Authorized;
        }
    }

    // 3. Capability not found — requires wallet approval
    UcanValidationResult::RequiresApproval
}

/// Check if a granted capability satisfies a required capability.
///
/// A capability satisfies the requirement if:
/// - Resources match exactly OR the granted resource is "*" (wildcard)
/// - Actions match exactly OR the granted action is "*" (wildcard)
fn capability_satisfies(granted: &Capability, required: &Capability) -> bool {
    let resource_match = granted.resource == "*" || granted.resource == required.resource;
    let action_match = granted.action == "*" || granted.action == required.action;
    resource_match && action_match
}

/// Create an ActionRequest with a SHA-256 hash of the tool arguments.
pub fn create_action_request(
    tool_name: &str,
    args_json: &str,
    human_summary: &str,
    ttl_seconds: u64,
    now_epoch: u64,
) -> ActionRequest {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update(b":");
    hasher.update(args_json.as_bytes());
    hasher.update(b":");
    hasher.update(now_epoch.to_be_bytes());
    let hash = hasher.finalize();

    ActionRequest {
        request_id: hex::encode(&hash[..16]), // 128-bit request ID
        tool_name: tool_name.to_string(),
        human_summary: human_summary.to_string(),
        payload_hash: hex::encode(hash),
        expires_at: now_epoch + ttl_seconds,
    }
}

/// Verify an ActionResponse signature against the original payload hash.
///
/// # Arguments
/// * `response` - The ActionResponse from the wallet
/// * `expected_hash` - The original `payload_hash` from the ActionRequest
/// * `user_pubkey` - The user's Ed25519 public key (from their pairwise DID)
pub fn verify_action_response(
    response: &ActionResponse,
    expected_hash: &str,
    user_pubkey: &[u8; 32],
) -> Result<bool, String> {
    if !response.approved {
        return Ok(false);
    }

    let sig_bytes = response
        .signature
        .as_ref()
        .ok_or("Missing signature in approved response")?;

    if sig_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);

    let hash_bytes =
        hex::decode(expected_hash).map_err(|_| "Invalid payload hash hex".to_string())?;

    Ok(crate::signing::verify_bytes(
        user_pubkey,
        &hash_bytes,
        &sig_arr,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_capability(resource: &str, action: &str) -> Capability {
        Capability {
            resource: resource.to_string(),
            action: action.to_string(),
        }
    }

    fn test_ucan() -> UcanToken {
        UcanToken {
            issuer: "did:twin:zuser123".to_string(),
            audience: "did:twin:zservice456".to_string(),
            capabilities: vec![
                test_capability("messaging", "send"),
                test_capability("calendar", "read"),
            ],
            expiry: 0, // no expiry
            proof_chain: vec![],
            token_id: "ucan-001".to_string(),
        }
    }

    #[test]
    fn test_ucan_encode_decode_roundtrip() {
        let token = test_ucan();
        let json = encode_ucan(&token).unwrap();
        let decoded = decode_ucan(&json).unwrap();
        assert_eq!(decoded.issuer, token.issuer);
        assert_eq!(decoded.capabilities.len(), 2);
    }

    #[test]
    fn test_validate_ucan_authorized() {
        let token = test_ucan();
        let required = test_capability("messaging", "send");
        match validate_ucan(&token, &required, 100) {
            UcanValidationResult::Authorized => {}
            other => panic!("Expected Authorized, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_ucan_requires_approval() {
        let token = test_ucan();
        let required = test_capability("payment", "transfer");
        match validate_ucan(&token, &required, 100) {
            UcanValidationResult::RequiresApproval => {}
            other => panic!("Expected RequiresApproval, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_ucan_expired() {
        let mut token = test_ucan();
        token.expiry = 50;
        let required = test_capability("messaging", "send");
        match validate_ucan(&token, &required, 100) {
            UcanValidationResult::Denied(_) => {}
            other => panic!("Expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_wildcard_capability() {
        let mut token = test_ucan();
        token.capabilities = vec![test_capability("*", "*")];
        let required = test_capability("payment", "transfer");
        match validate_ucan(&token, &required, 100) {
            UcanValidationResult::Authorized => {}
            other => panic!("Expected Authorized, got {:?}", other),
        }
    }

    #[test]
    fn test_create_action_request() {
        let req = create_action_request(
            "process_refund",
            r#"{"amount": 42}"#,
            "Approve $42 refund",
            300,
            1000,
        );
        assert_eq!(req.tool_name, "process_refund");
        assert_eq!(req.expires_at, 1300);
        assert!(!req.payload_hash.is_empty());
        assert!(!req.request_id.is_empty());
    }

    #[test]
    fn test_verify_action_response_with_signing() {
        use crate::did::create_did_twin;

        let identity = create_did_twin();
        let req = create_action_request("test_tool", "{}", "Test", 300, 1000);

        // User signs the payload_hash
        let hash_bytes = hex::decode(&req.payload_hash).unwrap();
        let signature = crate::signing::sign_bytes(&identity.signing_seed, &hash_bytes);

        let response = ActionResponse {
            request_id: req.request_id.clone(),
            approved: true,
            signature: Some(signature.to_vec()),
        };

        let result =
            verify_action_response(&response, &req.payload_hash, &identity.public_key).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_action_response_rejected() {
        let identity = crate::did::create_did_twin();
        let response = ActionResponse {
            request_id: "test".to_string(),
            approved: false,
            signature: None,
        };

        let result =
            verify_action_response(&response, "abcd1234", &identity.public_key).unwrap();
        assert!(!result);
    }
}
