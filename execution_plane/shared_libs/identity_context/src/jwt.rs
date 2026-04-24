// ─────────────────────────────────────────────────────────────
// JWT introspection — minimal payload decoding
//
// Spec reference: §17.2 steps 3-4
//
// Extracts identity claims from session JWTs WITHOUT validation.
// Validation is the responsibility of the issuer (Host's ssi_vault).
// This module replaces the ad-hoc helpers previously in
// trust_gateway/src/session.rs.
// ─────────────────────────────────────────────────────────────

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Decoded JWT payload claims relevant to identity derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer — the owner DID.
    #[serde(default)]
    pub iss: String,

    /// Subject — the requester DID (defaults to `iss` if absent).
    #[serde(default)]
    pub sub: String,

    /// Tenant namespace.
    #[serde(default)]
    pub tenant_id: String,

    /// Session correlation identifier.
    #[serde(default)]
    pub jti: String,

    /// Scope / permissions granted by this JWT.
    #[serde(default)]
    pub scope: Vec<String>,

    /// User DID when acting on behalf of an end user.
    #[serde(default)]
    pub user_did: Option<String>,

    /// Expiry timestamp (Unix epoch seconds).
    #[serde(default)]
    pub exp: Option<i64>,

    /// Issued-at timestamp (Unix epoch seconds).
    #[serde(default)]
    pub iat: Option<i64>,
}

/// Decode a JWT's payload section into structured claims.
///
/// **WARNING:** This does NOT verify signatures. For authorization, verify via 
/// the ssi_vault first. This function only base64-decodes the middle segment 
/// and deserializes the JSON payload.
#[must_use]
pub fn decode_jwt_claims(jwt: &str) -> Option<JwtClaims> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = decoder.decode(parts[1]).ok()?;
    let mut claims: JwtClaims = serde_json::from_slice(&payload_bytes).ok()?;

    // Normalize: if sub is empty, default to iss.
    if claims.sub.is_empty() {
        claims.sub = claims.iss.clone();
    }
    // If iss is empty, default to sub.
    if claims.iss.is_empty() {
        claims.iss = claims.sub.clone();
    }

    Some(claims)
}

// ─── Backward-compatible convenience functions ──────────────
// These preserve the exact signatures used by trust_gateway/src/session.rs
// so migration is a simple re-export.

/// Extract owner_did (iss) and requester_did (sub) from a session JWT.
#[must_use]
pub fn extract_dids_from_jwt(jwt: &str) -> Option<(String, String)> {
    let claims = decode_jwt_claims(jwt)?;
    Some((claims.iss, claims.sub))
}

/// Extract tenant_id from a session JWT.
#[must_use]
pub fn extract_tenant_id_from_jwt(jwt: &str) -> Option<String> {
    let claims = decode_jwt_claims(jwt)?;
    if claims.tenant_id.is_empty() {
        None
    } else {
        Some(claims.tenant_id)
    }
}

/// Extract JTI (session correlation ID) from a session JWT.
#[must_use]
pub fn extract_jti_from_jwt(jwt: &str) -> Option<String> {
    let claims = decode_jwt_claims(jwt)?;
    if claims.jti.is_empty() {
        None
    } else {
        Some(claims.jti)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal test JWT (header.payload.signature) with given claims.
    fn make_test_jwt(claims: &serde_json::Value) -> String {
        let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = encoder.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload = encoder.encode(serde_json::to_vec(claims).unwrap());
        format!("{}.{}.test_sig", header, payload)
    }

    #[test]
    fn test_decode_full_claims() {
        let jwt = make_test_jwt(&serde_json::json!({
            "iss": "did:twin:z1234",
            "sub": "did:twin:z5678",
            "tenant_id": "tenant-eu-01",
            "jti": "session-abc",
            "scope": ["tools:execute"],
            "exp": 9999999999_i64,
        }));

        let claims = decode_jwt_claims(&jwt).expect("should decode");
        assert_eq!(claims.iss, "did:twin:z1234");
        assert_eq!(claims.sub, "did:twin:z5678");
        assert_eq!(claims.tenant_id, "tenant-eu-01");
        assert_eq!(claims.jti, "session-abc");
        assert_eq!(claims.scope, vec!["tools:execute"]);
    }

    #[test]
    fn test_sub_defaults_to_iss() {
        let jwt = make_test_jwt(&serde_json::json!({
            "iss": "did:twin:z1234",
            "tenant_id": "t1",
        }));

        let claims = decode_jwt_claims(&jwt).expect("should decode");
        assert_eq!(claims.sub, "did:twin:z1234", "sub should default to iss");
    }

    #[test]
    fn test_backward_compat_extract_dids() {
        let jwt = make_test_jwt(&serde_json::json!({
            "iss": "did:twin:zOwner",
            "sub": "did:twin:zRequester",
        }));

        let (iss, sub) = extract_dids_from_jwt(&jwt).expect("should extract");
        assert_eq!(iss, "did:twin:zOwner");
        assert_eq!(sub, "did:twin:zRequester");
    }

    #[test]
    fn test_backward_compat_extract_tenant() {
        let jwt = make_test_jwt(&serde_json::json!({
            "iss": "did:twin:z1",
            "tenant_id": "tenant-eu-01",
        }));

        assert_eq!(
            extract_tenant_id_from_jwt(&jwt),
            Some("tenant-eu-01".to_string())
        );
    }

    #[test]
    fn test_backward_compat_extract_jti() {
        let jwt = make_test_jwt(&serde_json::json!({
            "iss": "did:twin:z1",
            "jti": "session-xyz",
        }));

        assert_eq!(
            extract_jti_from_jwt(&jwt),
            Some("session-xyz".to_string())
        );
    }

    #[test]
    fn test_malformed_jwt_returns_none() {
        assert!(decode_jwt_claims("not-a-jwt").is_none());
        assert!(decode_jwt_claims("").is_none());
        assert!(decode_jwt_claims("only.one").is_none());
    }
}
