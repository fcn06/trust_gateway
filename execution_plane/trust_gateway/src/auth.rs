// ─────────────────────────────────────────────────────────────
// Token Validation Trait — Dependency Injection for Auth
//
// This module defines the `TokenValidator` trait, a seam that
// enables the enterprise/professional edition to inject its own
// SSI / Verifiable Presentation validator without any source
// code leakage into the open-source community repository.
//
// The community edition ships with `StandardJwtValidator` which
// performs the legacy HMAC-HS256 session JWT verification that
// has always powered the gateway.  Enterprise builds can provide
// an alternate implementation (e.g. one that peeks the token to
// detect VPs and falls back to `StandardJwtValidator` for
// regular browser sessions).
// ─────────────────────────────────────────────────────────────

use axum::http::{HeaderMap, StatusCode};
use identity_context::jwt::{JwtClaims, VerifiedJwt};
use identity_context::AuthVerifier; // RULE[010_JWT_CONTRACTS.md]

/// Extract Bearer token from the Authorization header.
///
/// This helper is intentionally public so that both the community
/// `StandardJwtValidator` and any enterprise validator can reuse
/// it without duplicating the parsing logic.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let tok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if tok.is_none() {
        tracing::debug!("🚫 No Bearer token found in Authorization header");
    }
    tok.map(|s| s.to_string())
}

/// Pluggable token validation trait.
///
/// The Trust Gateway calls `validate()` on every authenticated
/// endpoint.  The community edition uses `StandardJwtValidator`
/// (HMAC-HS256 session JWTs).  The professional/enterprise
/// edition can inject its own implementation that additionally
/// handles `did:jwk` Verifiable Presentations while falling
/// back to the standard validator for regular web sessions.
///
/// # Contract (RULE[010_JWT_CONTRACTS.md])
///
/// - Return `Ok(VerifiedJwt)` when the request carries a valid,
///   signature-verified token.  The `VerifiedJwt` wrapper proves
///   that verification was performed.
/// - Return `Err(StatusCode::UNAUTHORIZED)` for invalid/missing tokens.
/// - The `secret` parameter is the shared HMAC key used by the
///   community validator; enterprise validators may ignore it if
///   they use asymmetric cryptography.
#[async_trait::async_trait]
pub trait TokenValidator: Send + Sync {
    /// Validates the request headers and returns a `VerifiedJwt`.
    ///
    /// Callers receive a proof-token whose inner `JwtClaims` are
    /// accessible via `Deref` or `.claims()`.
    async fn validate(&self, headers: &HeaderMap, secret: &str) -> Result<VerifiedJwt, StatusCode>;
}

/// Standard HMAC-HS256 session JWT validator (community edition default).
///
/// This is the exact same logic that was previously inlined in
/// `api.rs::verify_auth()`.  Moving it here as a trait implementation
/// preserves 100% retro-compatibility: every JWT that worked before
/// continues to work identically.
///
/// H3b fix: Claims are now extracted directly from jwt_simple's verified
/// output (single decode path) rather than re-decoding the unverified
/// payload via identity_context::jwt::decode_jwt_claims().
pub struct StandardJwtValidator;

#[async_trait::async_trait]
impl TokenValidator for StandardJwtValidator {
    async fn validate(&self, headers: &HeaderMap, secret: &str) -> Result<VerifiedJwt, StatusCode> {
        let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;

        // RULE[010_JWT_CONTRACTS.md]: Delegate to HmacAuthVerifier
        // which performs HMAC-SHA256 signature verification and returns
        // a VerifiedJwt proof-token.
        let verifier = identity_context::jwt::HmacAuthVerifier::new(secret);
        verifier.verify(&token).map_err(|e| {
            tracing::debug!("JWT verification failed: {}", e);
            StatusCode::UNAUTHORIZED
        })
    }
}

/// SSI Token Validator (Phase 1 DID/JWK Pipeline)
///
/// This validator inspects incoming tokens. If a Verifiable Presentation
/// is detected, it routes it through the zero-network DID/JWK verification
/// pipeline and resolves the issuer via did:web.
///
/// If the token is a standard JWT, it seamlessly falls back to the
/// `StandardJwtValidator` to preserve backward compatibility for UI sessions.
pub struct SsiTokenValidator {
    pub fallback: StandardJwtValidator,
    pub http_client: reqwest::Client,
}

#[async_trait::async_trait]
impl TokenValidator for SsiTokenValidator {
    async fn validate(&self, headers: &HeaderMap, secret: &str) -> Result<VerifiedJwt, StatusCode> {
        let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;

        // Phase 1: Intercept VP tokens
        if crate::vp_verifier::is_verifiable_presentation(&token) {
            tracing::debug!("🛡️ Detected Verifiable Presentation, routing to SSI pipeline");
            
            let verified_vp = crate::vp_verifier::verify_presentation(&token, &self.http_client)
                .await
                .map_err(|e| {
                    tracing::warn!("❌ VP Verification Failed: {}", e);
                    StatusCode::UNAUTHORIZED
                })?;

            // Step 5: Map VP into standard JwtClaims wrapped in VerifiedJwt.
            // The VP's cryptographic signature has been verified by
            // vp_verifier::verify_presentation, so wrapping in VerifiedJwt
            // is legitimate — the claims are derived from a verified source.
            //
            // H3a fix: SSI agents get narrow 'agent:propose' scope instead of
            // wildcard '*'. This is the minimum permission needed to enter the
            // governance pipeline. Downstream policy evaluation (TOML rules)
            // performs the actual authorization based on action attributes.
            let claims = JwtClaims {
                iss: verified_vp.issuer_did,
                sub: verified_vp.agent_did,
                tenant_id: verified_vp.tenant_id,
                jti: uuid::Uuid::new_v4().to_string(), // Ephemeral session ID for the request
                scope: vec!["agent:propose".to_string()],
                user_did: None,
                exp: None, // VPs are typically single-use per request, or we rely on outer JWT expiry (TODO)
                iat: None,
            };
            return Ok(identity_context::jwt::VerifiedJwt::from_verified_source(claims));
        }

        // Fallback to legacy JWT verification
        self.fallback.validate(headers, secret).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_bearer_token_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer my-test-token".parse().unwrap(),
        );
        assert_eq!(extract_bearer_token(&headers), Some("my-test-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc123".parse().unwrap(),
        );
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[tokio::test]
    async fn test_standard_validator_rejects_missing_token() {
        let validator = StandardJwtValidator;
        let headers = HeaderMap::new();
        let result = validator.validate(&headers, "test-secret").await;
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn test_standard_validator_rejects_invalid_token() {
        let validator = StandardJwtValidator;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer not-a-valid-jwt".parse().unwrap(),
        );
        let result = validator.validate(&headers, "test-secret").await;
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn test_ssi_validator_fallback_to_standard() {
        // Create an SsiTokenValidator
        let validator = SsiTokenValidator {
            fallback: StandardJwtValidator,
            http_client: reqwest::Client::new(),
        };

        let mut headers = HeaderMap::new();
        // Provide a non-VP token that fails StandardJwtValidator verification
        // (meaning it correctly fell back rather than trying to parse as VP)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_sig";
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let result = validator.validate(&headers, "test-secret").await;
        // Should return UNAUTHORIZED because it fell back to legacy validation and the signature is invalid
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn test_ssi_validator_detects_vp_and_fails_verification() {
        let validator = SsiTokenValidator {
            fallback: StandardJwtValidator,
            http_client: reqwest::Client::new(),
        };

        let mut headers = HeaderMap::new();
        // Provide a structurally valid VP (has "vp" field) but with a fake signature
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = b64.encode(b"{\"alg\":\"EdDSA\"}");
        let payload = b64.encode(serde_json::to_vec(&serde_json::json!({
            "iss": "did:jwk:test", "vp": {}
        })).unwrap());
        let token = format!("{}.{}.fake_sig", header, payload);
        
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let result = validator.validate(&headers, "test-secret").await;
        // It should detect the VP, try to verify the DID (which is invalid), and fail returning UNAUTHORIZED
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }
}
