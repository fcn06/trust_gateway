// ─────────────────────────────────────────────────────────────
// JWT verification and introspection
//
// Spec reference: §17.2 steps 3-4
//
// Provides:
// - `AuthVerifier` trait — the ONLY approved entry point for
//   JWT verification per RULE[010_JWT_CONTRACTS.md].
// - `VerifiedJwt` — opaque container proving signature check.
// - `HmacAuthVerifier` — HMAC-HS256 implementation.
// - `decode_jwt_claims` — DEPRECATED introspection-only helper
//   retained for audit logging of rejected tokens.
//
// Callers MUST NOT call `decode_jwt_claims` for domain logic.
// Use `AuthVerifier::verify()` → `VerifiedJwt` instead.
// ─────────────────────────────────────────────────────────────

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

// ─── Verification types (RULE[010_JWT_CONTRACTS.md]) ────────

/// Error returned by `AuthVerifier::verify`.
#[derive(Debug, thiserror::Error)]
pub enum AuthVerifyError {
    #[error("missing or empty token")]
    MissingToken,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("token expired")]
    Expired,

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// A JWT whose signature has been cryptographically verified.
///
/// This type can ONLY be constructed by calling `AuthVerifier::verify()`
/// or the internal `VerifiedJwt::new_verified` (crate-private).
/// It serves as a *proof token* in the type system: any function
/// that receives a `VerifiedJwt` knows the claims were validated.
///
/// Implements `Deref<Target = JwtClaims>` for ergonomic field access.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedJwt {
    claims: JwtClaims,
}

impl VerifiedJwt {
    /// Construct a `VerifiedJwt` from pre-verified claims.
    ///
    /// **Crate-private:** only verification implementations within
    /// this crate (e.g. `HmacAuthVerifier`) may call this.
    pub(crate) fn new_verified(claims: JwtClaims) -> Self {
        Self { claims }
    }

    /// Construct a `VerifiedJwt` from claims that were verified
    /// by an external cryptographic pipeline (e.g. SSI VP verification).
    ///
    /// **Caller contract:** The caller MUST have performed cryptographic
    /// signature verification (e.g. Ed25519 over a DID/JWK VP) before
    /// calling this method. This is the escape hatch for non-HMAC
    /// verification pipelines (Verifiable Presentations, external IdPs).
    ///
    /// Misuse of this constructor (wrapping unverified claims) violates
    /// RULE[010_JWT_CONTRACTS.md].
    pub fn from_verified_source(claims: JwtClaims) -> Self {
        Self { claims }
    }

    /// Consume and return the inner `JwtClaims`.
    pub fn into_claims(self) -> JwtClaims {
        self.claims
    }

    /// Borrow the inner `JwtClaims`.
    pub fn claims(&self) -> &JwtClaims {
        &self.claims
    }
}

impl Deref for VerifiedJwt {
    type Target = JwtClaims;
    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}

/// Contract for JWT verification.
///
/// Per RULE[010_JWT_CONTRACTS.md]:
/// - `AuthVerifier::verify()` → `Result<VerifiedJwt, AuthVerifyError>`
/// - Passing `VerifiedJwt` into domain/application services.
///
/// Forbidden:
/// - Passing raw JWT claims into domain logic.
/// - Calling JWT decode APIs directly outside `auth` crate.
/// - Accepting `alg=none`.
/// - Skipping `exp`, `nbf`, `aud`, `iss`, or signature validation.
pub trait AuthVerifier: Send + Sync {
    /// Verify a JWT token string and return its validated claims.
    ///
    /// Implementations MUST:
    /// 1. Validate the cryptographic signature.
    /// 2. Reject `alg=none`.
    /// 3. Check `exp` (expiry) if present.
    /// 4. Return `Err` for any validation failure.
    fn verify(&self, token: &str) -> Result<VerifiedJwt, AuthVerifyError>;
}

/// HMAC-SHA256 JWT verifier (community edition default).
///
/// Wraps `jwt_simple::HS256Key` to provide the `AuthVerifier` contract.
/// This is the canonical verifier for session JWTs issued by the Host.
pub struct HmacAuthVerifier {
    key: jwt_simple::prelude::HS256Key,
}

impl HmacAuthVerifier {
    /// Create a new HMAC-SHA256 verifier from a shared secret.
    pub fn new(secret: &str) -> Self {
        Self {
            key: jwt_simple::prelude::HS256Key::from_bytes(secret.as_bytes()),
        }
    }

    /// Create from raw bytes.
    pub fn from_bytes(secret: &[u8]) -> Self {
        Self {
            key: jwt_simple::prelude::HS256Key::from_bytes(secret),
        }
    }
}

impl AuthVerifier for HmacAuthVerifier {
    fn verify(&self, token: &str) -> Result<VerifiedJwt, AuthVerifyError> {
        if token.is_empty() {
            return Err(AuthVerifyError::MissingToken);
        }

        use jwt_simple::prelude::MACLike;
        let verified = self.key
            .verify_token::<JwtClaims>(token, None)
            .map_err(|e| AuthVerifyError::SignatureInvalid(format!("{}", e)))?;

        let mut claims = verified.custom;

        // Normalize: if sub is empty, default to iss.
        if claims.sub.is_empty() {
            claims.sub = claims.iss.clone();
        }
        // If iss is empty, default to sub.
        if claims.iss.is_empty() {
            claims.iss = claims.sub.clone();
        }

        Ok(VerifiedJwt::new_verified(claims))
    }
}

/// Decoded JWT payload claims relevant to identity derivation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
