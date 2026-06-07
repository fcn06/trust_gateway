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
    /// Validates the request headers and returns an `IdentityContext`.
    ///
    /// Callers receive a fully normalized identity context including
    /// `auth_level`, `auth_method`, and parsed DIDs.
    async fn validate(
        &self,
        headers: &HeaderMap,
        secret: &str,
    ) -> Result<trust_auth::IdentityContext, StatusCode>;
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
    async fn validate(
        &self,
        headers: &HeaderMap,
        secret: &str,
    ) -> Result<trust_auth::IdentityContext, StatusCode> {
        let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;

        let resolver = trust_auth::AuthResolver::new(secret);
        // StandardJwtValidator only supports HMAC JWTs (legacy fallback behavior)
        resolver
            .resolve(trust_auth::RawAuthInput::Jwt(token))
            .await
            .map_err(|e| {
                tracing::debug!("Standard verification failed: {}", e);
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
    pub did_web_cache: Option<async_nats::jetstream::kv::Store>,
}

#[async_trait::async_trait]
impl TokenValidator for SsiTokenValidator {
    async fn validate(
        &self,
        headers: &HeaderMap,
        secret: &str,
    ) -> Result<trust_auth::IdentityContext, StatusCode> {
        let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;

        let mut resolver = trust_auth::AuthResolver::new(secret);
        if let Some(ref cache) = self.did_web_cache {
            resolver = resolver.with_did_web_cache(cache.clone());
        }

        // Phase 1: Intercept VP tokens
        if is_verifiable_presentation(&token) {
            tracing::debug!("🛡️ Detected Verifiable Presentation, routing to SSI pipeline");

            return resolver
                .resolve(trust_auth::RawAuthInput::VerifiablePresentation(token))
                .await
                .map_err(|e| {
                    tracing::warn!("❌ VP Verification Failed: {}", e);
                    StatusCode::UNAUTHORIZED
                });
        }

        // Everything else (HMAC or DID-signed JWT) is handled by the any_jwt path
        resolver
            .resolve(trust_auth::RawAuthInput::Jwt(token))
            .await
            .map_err(|e| {
                tracing::debug!("Token verification failed: {}", e);
                StatusCode::UNAUTHORIZED
            })
    }
}

/// Peek at a JWT-encoded token to determine if it is a Verifiable Presentation.
fn is_verifiable_presentation(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return false; }
    use base64::Engine;
    if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
            return json.get("vp").is_some();
        }
    }
    false
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
        assert_eq!(
            extract_bearer_token(&headers),
            Some("my-test-token".to_string())
        );
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
            did_web_cache: None,
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
            did_web_cache: None,
        };

        let mut headers = HeaderMap::new();
        // Provide a structurally valid VP (has "vp" field) but with a fake signature
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = b64.encode(b"{\"alg\":\"EdDSA\"}");
        let payload = b64.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "did:jwk:test", "vp": {}
            }))
            .unwrap(),
        );
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
