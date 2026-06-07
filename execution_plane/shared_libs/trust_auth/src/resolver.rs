use crate::auth_method::{AuthMethod, RawAuthInput};
use crate::IdentityContext;
use anyhow::Result;
use identity_context::{
    jwt::{AuthVerifier, HmacAuthVerifier},
    models::{SourceContext, SourceType},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Missing or empty token")]
    MissingToken,
    #[error("Invalid token structure or signature")]
    InvalidToken(#[from] anyhow::Error),
    #[error("Unsupported authentication method")]
    UnsupportedMethod,
    #[error("Token expired or not yet valid")]
    TimeViolation,
    /// REC-3: Multiple credential sources present and they disagree.
    #[error("Conflicting credentials: {0}")]
    ConflictingCredentials(String),
    /// REC-3: Session JWT presented where ExecutionGrant expected, or vice versa.
    #[error("Wrong token class: expected {expected}, got {actual}")]
    WrongTokenClass {
        expected: String,
        actual: String,
    },
}

/// The AuthResolver normalizes various incoming authentication payloads into a
/// single, unified IdentityContext.
///
/// Phase 2 implementation requirements:
/// - Enforces ±5s clock skew
/// - Assigns the numeric AuthLevel
/// - Captures the AuthMethod
/// - REC-3: Rejects conflicting credentials when multiple sources disagree
pub struct AuthResolver {
    jwt_secret: String,
    did_web_cache: Option<async_nats::jetstream::kv::Store>,
}

impl AuthResolver {
    pub fn new(jwt_secret: impl Into<String>) -> Self {
        Self {
            jwt_secret: jwt_secret.into(),
            did_web_cache: None,
        }
    }

    pub fn with_did_web_cache(mut self, cache: async_nats::jetstream::kv::Store) -> Self {
        self.did_web_cache = Some(cache);
        self
    }

    /// Resolve a raw authentication input into a normalized IdentityContext.
    pub async fn resolve(&self, input: RawAuthInput) -> Result<IdentityContext, AuthError> {
        match input {
            RawAuthInput::Jwt(token) => self.resolve_any_jwt(&token),
            RawAuthInput::VerifiablePresentation(vp) => self.resolve_vp(&vp).await,
            RawAuthInput::ApiKey(_) => Err(AuthError::UnsupportedMethod),
            RawAuthInput::OAuth2Bearer(_) => Err(AuthError::UnsupportedMethod),
        }
    }

    /// REC-3: Resolve multiple credential sources, rejecting if they disagree.
    ///
    /// When the transport layer extracts credentials from multiple locations
    /// (Authorization header, body field, _meta wrapper), each is resolved
    /// independently. If the resolved identities produce different `tenant_id`
    /// or `requester_did`, the request is rejected outright.
    ///
    /// If only one source is present, it behaves identically to `resolve()`.
    pub async fn resolve_multi(&self, inputs: Vec<RawAuthInput>) -> Result<IdentityContext, AuthError> {
        if inputs.is_empty() {
            return Err(AuthError::MissingToken);
        }

        if inputs.len() == 1 {
            return self.resolve(inputs.into_iter().next().unwrap()).await;
        }

        // Resolve all inputs independently
        let mut resolved: Vec<IdentityContext> = Vec::new();
        for input in inputs {
            match self.resolve(input).await {
                Ok(ctx) => resolved.push(ctx),
                Err(AuthError::UnsupportedMethod) => continue, // skip unsupported
                Err(e) => return Err(e),
            }
        }

        if resolved.is_empty() {
            return Err(AuthError::MissingToken);
        }

        // REC-3: Check that all resolved identities agree on critical fields
        let first = &resolved[0];
        for other in &resolved[1..] {
            if first.tenant_id != other.tenant_id {
                tracing::warn!(
                    "🔒 REC-3: Conflicting tenant_id across credential sources: '{}' vs '{}'",
                    first.tenant_id,
                    other.tenant_id
                );
                return Err(AuthError::ConflictingCredentials(format!(
                    "tenant_id mismatch: '{}' vs '{}'",
                    first.tenant_id, other.tenant_id
                )));
            }
            if first.requester_did != other.requester_did {
                tracing::warn!(
                    "🔒 REC-3: Conflicting requester_did across credential sources: '{}' vs '{}'",
                    first.requester_did,
                    other.requester_did
                );
                return Err(AuthError::ConflictingCredentials(format!(
                    "requester_did mismatch: '{}' vs '{}'",
                    first.requester_did, other.requester_did
                )));
            }
        }

        // All agree — return the first (which has the highest fidelity)
        Ok(resolved.into_iter().next().unwrap())
    }

    /// Resolve a standard JWT, attempting DID-based EdDSA verification first
    /// if it appears to be an SSI token, falling back to legacy HMAC.
    fn resolve_any_jwt(&self, token: &str) -> Result<IdentityContext, AuthError> {
        // Peak at issuer to determine if we should try EdDSA/DID verification
        if self.is_did_signed_jwt(token) {
            match crate::did::verify_eddsa_session_jwt(token) {
                Ok(claims) => {
                    let (auth_level, auth_method) = self.extract_enriched_auth(token);
                    return Ok(IdentityContext {
                        tenant_id: claims.tenant_id,
                        owner_did: claims.iss,
                        requester_did: claims.sub,
                        auth_level,
                        auth_method: AuthMethod::VpEdDsa, // Treat DID-signed session as high-assurance
                        oauth_scopes: claims.scope,
                        session_jwt: token.to_string(),
                        source: SourceContext::default(),
                    });
                }
                Err(e) => {
                    tracing::warn!("EdDSA verification failed for DID-signed JWT: {}", e);
                    // Fall through to HMAC just in case of misconfiguration
                }
            }
        }

        self.resolve_hmac_jwt(token)
    }

    /// Checks if a JWT is signed by a DID using EdDSA (SSI session)
    fn is_did_signed_jwt(&self, token: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 { return false; }
        
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        
        // 1. Check Header for alg: EdDSA
        let alg_ok = if let Ok(decoded_header) = b64.decode(parts[0]) {
            if let Ok(header_json) = serde_json::from_slice::<serde_json::Value>(&decoded_header) {
                header_json.get("alg").and_then(|v| v.as_str()) == Some("EdDSA")
            } else { false }
        } else { false };
        
        if !alg_ok { return false; }

        // 2. Check Payload for iss: did:*
        if let Ok(decoded_payload) = b64.decode(parts[1]) {
            if let Ok(payload_json) = serde_json::from_slice::<serde_json::Value>(&decoded_payload) {
                return payload_json.get("iss")
                    .and_then(|v| v.as_str())
                    .map(|s| s.starts_with("did:"))
                    .unwrap_or(false);
            }
        }
        false
    }

    fn resolve_hmac_jwt(&self, token: &str) -> Result<IdentityContext, AuthError> {
        let verifier = HmacAuthVerifier::new(&self.jwt_secret);
        // AuthVerifier implementation (e.g. from identity_context) handles the clock skew internally.
        let verified = verifier
            .verify(token)
            .map_err(|e| AuthError::InvalidToken(e.into()))?;

        let claims = verified.claims();

        // Phase 5: Try to extract enriched session claims (auth_level, amr)
        // from the raw JWT payload. WebAuthn sessions carry auth_level=5.
        let (auth_level, auth_method) = self.extract_enriched_auth(token);

        Ok(IdentityContext {
            tenant_id: claims.tenant_id.clone(),
            owner_did: claims.iss.clone(),
            requester_did: claims.sub.clone(),
            auth_level,
            auth_method,
            oauth_scopes: claims.scope.clone(),
            session_jwt: token.to_string(),
            source: SourceContext::default(), // Typically overridden by the transport
        })
    }

    /// Phase 5: Extract enriched auth metadata from the JWT payload.
    ///
    /// If the Host included `auth_level` and `amr` in the JWT, use them.
    /// Otherwise fall back to Level3Session / HmacJwt defaults.
    fn extract_enriched_auth(&self, token: &str) -> (trust_core::actor::AuthLevel, AuthMethod) {
        // Best-effort: decode the payload segment to check for auth_level/amr
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return (
                trust_core::actor::AuthLevel::Level3Session,
                AuthMethod::HmacJwt,
            );
        }

        // Decode the payload (middle segment)
        use base64::Engine;
        let payload = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    trust_core::actor::AuthLevel::Level3Session,
                    AuthMethod::HmacJwt,
                )
            }
        };

        // Try to parse as SessionClaims
        if let Ok(session) =
            serde_json::from_slice::<crate::session_claims::SessionClaims>(&payload)
        {
            let level = session.to_auth_level();
            let method = if session.is_webauthn() {
                AuthMethod::WebAuthn
            } else {
                AuthMethod::HmacJwt
            };
            tracing::debug!(
                "Phase 5: Enriched session JWT — auth_level={}, amr={:?}",
                session.auth_level,
                session.amr
            );
            (level, method)
        } else {
            // Legacy JWT without enriched claims
            (
                trust_core::actor::AuthLevel::Level3Session,
                AuthMethod::HmacJwt,
            )
        }
    }

    async fn resolve_vp(&self, vp_token: &str) -> Result<IdentityContext, AuthError> {
        // Here we delegate to the trust_auth::did module we ported from vp_verifier.rs.
        // We need an HTTP client for did:web resolution.
        let client = reqwest::Client::new();

        let vp = crate::did::verify_presentation(vp_token, &client, self.did_web_cache.as_ref())
            .await
            .map_err(|e| AuthError::InvalidToken(anyhow::anyhow!(e.to_string())))?;

        // Verified presentations represent AuthLevel 4.
        Ok(IdentityContext {
            tenant_id: vp.tenant_id,
            owner_did: vp.issuer_did,
            requester_did: vp.agent_did,
            auth_level: trust_core::actor::AuthLevel::Level4Verified,
            auth_method: AuthMethod::VpEdDsa,
            oauth_scopes: vec![],
            session_jwt: vp_token.to_string(),
            source: SourceContext {
                source_type: SourceType::SsiAgent,
                ..Default::default()
            },
        })
    }
}
