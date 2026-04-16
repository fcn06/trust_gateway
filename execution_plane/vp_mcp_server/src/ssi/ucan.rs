//! UCAN validation helpers for the VP MCP Server.
//!
//! Connection Model (V6): validates UCAN delegation tokens attached to
//! incoming MCP tool requests. Uses `ssi_crypto::ucan` for core validation
//! and provides HTTP-header extraction utilities.
//!
//! This module is scaffolded in Milestone 1 but fully integrated in Milestone 3.

use ssi_crypto::ucan::{
    self, ActionRequest, ActionResponse, Capability, UcanToken, UcanValidationResult,
};

/// HTTP header name for the UCAN delegation token.
pub const UCAN_HEADER: &str = "x-ucan-delegation";

/// Validate a UCAN token for a specific tool invocation.
///
/// # Arguments
/// * `ucan_json` - The raw UCAN JSON string (from the `x-ucan-delegation` header)
/// * `tool_name` - The MCP tool being invoked (e.g. "process_refund")
/// * `action` - The action type (e.g. "execute", "read")
///
/// # Returns
/// `Ok(UcanValidationResult)` on success, `Err` on invalid token.
pub fn validate_ucan_for_tool(
    ucan_json: &str,
    tool_name: &str,
    action: &str,
) -> Result<UcanValidationResult, String> {
    let token = ucan::decode_ucan(ucan_json)?;
    let required_cap = Capability {
        resource: tool_name.to_string(),
        action: action.to_string(),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(ucan::validate_ucan(&token, &required_cap, now))
}

/// Extract a UCAN token from HTTP request headers.
///
/// Looks for the `x-ucan-delegation` header and parses it as a UCAN JSON token.
pub fn extract_ucan_from_headers(
    headers: &axum::http::HeaderMap,
) -> Option<Result<UcanToken, String>> {
    headers
        .get(UCAN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|json| ucan::decode_ucan(json))
}

/// Check if a tool requires elevated clearance (wallet approval).
///
/// This replaces the previous `READ_SAFE_TOOLS` check in `middleware.rs`.
/// In the Connection Model, "elevated" tools are those not covered by the
/// user's UCAN delegation — they need explicit ActionRequest→ActionResponse.
pub fn tool_requires_approval(
    ucan_json: &str,
    tool_name: &str,
) -> Result<bool, String> {
    match validate_ucan_for_tool(ucan_json, tool_name, "execute")? {
        UcanValidationResult::RequiresApproval => Ok(true),
        UcanValidationResult::Authorized => Ok(false),
        UcanValidationResult::Denied(r) => Err(r),
    }
}

/// Create an ActionRequest for a tool that requires wallet approval.
pub fn create_tool_action_request(
    tool_name: &str,
    args_json: &str,
    human_summary: &str,
) -> ActionRequest {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ucan::create_action_request(tool_name, args_json, human_summary, 300, now)
}

/// Verify an ActionResponse from a user's wallet.
pub fn verify_tool_action_response(
    response: &ActionResponse,
    expected_hash: &str,
    user_pubkey: &[u8; 32],
) -> Result<bool, String> {
    ucan::verify_action_response(response, expected_hash, user_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ucan() -> String {
        let token = UcanToken {
            issuer: "did:twin:zuser123".to_string(),
            audience: "did:twin:zservice456".to_string(),
            capabilities: vec![
                Capability {
                    resource: "weather".to_string(),
                    action: "execute".to_string(),
                },
                Capability {
                    resource: "search".to_string(),
                    action: "execute".to_string(),
                },
            ],
            expiry: 0,
            proof_chain: vec![],
            token_id: "test-ucan-001".to_string(),
        };
        ucan::encode_ucan(&token).unwrap()
    }

    #[test]
    fn test_validate_authorized_tool() {
        let ucan_json = make_test_ucan();
        match validate_ucan_for_tool(&ucan_json, "weather", "execute").unwrap() {
            UcanValidationResult::Authorized => {}
            other => panic!("Expected Authorized, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_requires_approval() {
        let ucan_json = make_test_ucan();
        match validate_ucan_for_tool(&ucan_json, "process_refund", "execute").unwrap() {
            UcanValidationResult::RequiresApproval => {}
            other => panic!("Expected RequiresApproval, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_requires_approval() {
        let ucan_json = make_test_ucan();
        assert!(!tool_requires_approval(&ucan_json, "weather").unwrap());
        assert!(tool_requires_approval(&ucan_json, "process_refund").unwrap());
    }

    #[test]
    fn test_create_tool_action_request() {
        let req = create_tool_action_request(
            "process_refund",
            r#"{"amount": 42, "order_id": "ORD-123"}"#,
            "Approve $42 refund for order ORD-123",
        );
        assert_eq!(req.tool_name, "process_refund");
        assert!(!req.payload_hash.is_empty());
        assert!(!req.request_id.is_empty());
    }
}
