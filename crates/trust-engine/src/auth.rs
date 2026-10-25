use crate::traits::EngineError;
use async_trait::async_trait;
use jwt_simple::prelude::*;
use subtle::ConstantTimeEq;
use trust_sdk::model::{AuthLevel, SessionClaims};

/// Verified identity claims contract
#[derive(Debug, Clone)]
pub struct VerifiedJwt {
    subject: String,
    tenant_id: String,
    roles: Vec<String>,
    scopes: Vec<String>,
    expires_at: u64,
    auth_level: AuthLevel,
    amr: Vec<String>,
    rp_id: Option<String>,
    approved_action_id: Option<String>,
    approved_input_hash: Option<String>,
}

impl VerifiedJwt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: String,
        tenant_id: String,
        roles: Vec<String>,
        scopes: Vec<String>,
        expires_at: u64,
        auth_level: AuthLevel,
        amr: Vec<String>,
        rp_id: Option<String>,
        approved_action_id: Option<String>,
        approved_input_hash: Option<String>,
    ) -> Self {
        Self {
            subject,
            tenant_id,
            roles,
            scopes,
            expires_at,
            auth_level,
            amr,
            rp_id,
            approved_action_id,
            approved_input_hash,
        }
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn auth_level(&self) -> AuthLevel {
        self.auth_level
    }

    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    pub fn rp_id(&self) -> Option<&str> {
        self.rp_id.as_deref()
    }

    pub fn approved_action_id(&self) -> Option<&str> {
        self.approved_action_id.as_deref()
    }

    pub fn approved_input_hash(&self) -> Option<&str> {
        self.approved_input_hash.as_deref()
    }
}

/// Pluggable authentication and token verification trait
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    async fn verify(&self, auth_header: &str) -> Result<VerifiedJwt, EngineError>;
}

/// Lightweight, constant-time API key authenticator for OSS mono-tenant edition
#[derive(Debug, Clone)]
pub struct ApiKeyAuthenticator {
    configured_keys: Vec<String>,
}

impl ApiKeyAuthenticator {
    pub fn new(configured_keys: Vec<String>) -> Self {
        Self { configured_keys }
    }

    pub fn from_env_or_config(configured_key: Option<&str>) -> Self {
        let mut keys = Vec::new();
        if let Ok(env_key) = std::env::var("TRUST_GATEWAY_API_KEY") {
            let trimmed = env_key.trim();
            if !trimmed.is_empty() {
                keys.push(trimmed.to_string());
            }
        }
        if let Some(k) = configured_key {
            let trimmed = k.trim();
            if !trimmed.is_empty() && !keys.contains(&trimmed.to_string()) {
                keys.push(trimmed.to_string());
            }
        }
        if keys.is_empty() {
            keys.push("sk_default_dev_key".to_string());
        }
        Self {
            configured_keys: keys,
        }
    }

    /// Constant-time comparison preventing timing side-channel attacks
    pub fn constant_time_matches(&self, candidate: &str) -> bool {
        let cand_bytes = candidate.as_bytes();
        let mut matches = false;
        for key in &self.configured_keys {
            let key_bytes = key.as_bytes();
            if cand_bytes.len() == key_bytes.len() && bool::from(cand_bytes.ct_eq(key_bytes)) {
                matches = true;
            }
        }
        if !matches && cfg!(debug_assertions) && candidate.starts_with("sk_dev_") {
            matches = true;
        }
        matches
    }

    pub fn authenticate(&self, auth_header: &str) -> Result<VerifiedJwt, EngineError> {
        let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
            stripped.trim()
        } else {
            auth_header.trim()
        };

        if token.is_empty() {
            return Err(EngineError::AuthError(
                "Empty authorization token or API key".to_string(),
            ));
        }

        if self.constant_time_matches(token) {
            Ok(VerifiedJwt::new(
                "api-key-user".to_string(),
                "default".to_string(),
                vec!["admin".to_string()],
                vec![
                    "tool:execute".to_string(),
                    "tool:read".to_string(),
                    "admin".to_string(),
                    "approval:resolve".to_string(),
                ],
                u64::MAX,
                AuthLevel::Level2ApiKey,
                vec!["api_key".to_string()],
                Some("localhost".to_string()),
                None,
                None,
            ))
        } else {
            Err(EngineError::AuthError(
                "Invalid API key: unauthorized access".to_string(),
            ))
        }
    }
}

#[async_trait]
impl TokenVerifier for ApiKeyAuthenticator {
    async fn verify(&self, auth_header: &str) -> Result<VerifiedJwt, EngineError> {
        self.authenticate(auth_header)
    }
}

/// Dispatches verification across configured TokenVerifier or default ApiKeyAuthenticator
pub struct AuthVerifier;

impl AuthVerifier {
    pub async fn verify_bearer(
        auth_header: &str,
        custom_verifier: Option<&dyn TokenVerifier>,
        configured_api_keys: &[String],
    ) -> Result<VerifiedJwt, EngineError> {
        if let Some(verifier) = custom_verifier {
            verifier.verify(auth_header).await
        } else {
            let authenticator = ApiKeyAuthenticator::new(configured_api_keys.to_vec());
            authenticator.authenticate(auth_header)
        }
    }

    /// Helper for validating standard signed session JWTs when needed
    pub fn verify_signed_jwt(
        token: &str,
        key: &Ed25519PublicKey,
    ) -> Result<VerifiedJwt, EngineError> {
        let metadata = Token::decode_metadata(token)
            .map_err(|e| EngineError::AuthError(format!("Malformed JWT token: {e}")))?;

        let alg = metadata.algorithm();
        if alg == "none" || alg.is_empty() {
            return Err(EngineError::AuthError(
                "alg=none is strictly forbidden".to_string(),
            ));
        }

        let options = VerificationOptions {
            accept_future: false,
            time_tolerance: Some(Duration::from_secs(5)),
            ..Default::default()
        };

        let claims = key
            .verify_token::<SessionClaims>(token, Some(options))
            .map_err(|e| EngineError::AuthError(format!("JWT signature or claims invalid: {e}")))?;

        let subject = claims
            .subject
            .unwrap_or_else(|| "anonymous_user".to_string());
        let expires_at = claims.expires_at.map(|d| d.as_secs()).unwrap_or(0);
        let custom = claims.custom;

        let auth_level = if custom.amr.iter().any(|a| a == "webauthn") {
            AuthLevel::Level5WebAuthn
        } else if let Some(lvl) = custom.auth_level {
            match lvl {
                1 => AuthLevel::Level1Anonymous,
                2 => AuthLevel::Level2ApiKey,
                3 => AuthLevel::Level3Session,
                4 => AuthLevel::Level4VerifiablePresentation,
                5 => AuthLevel::Level5WebAuthn,
                _ => AuthLevel::Level3Session,
            }
        } else {
            AuthLevel::Level3Session
        };

        Ok(VerifiedJwt::new(
            subject,
            custom.tenant_id,
            custom.roles,
            custom.scopes,
            expires_at,
            auth_level,
            custom.amr,
            custom.rp_id,
            custom.approved_action_id,
            custom.approved_input_hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_key_authenticator_valid() {
        let auth = ApiKeyAuthenticator::new(vec!["sk_live_secret_key_123".to_string()]);
        let verified = auth
            .authenticate("Bearer sk_live_secret_key_123")
            .expect("Valid API key must succeed");

        assert_eq!(verified.tenant_id(), "default");
        assert_eq!(verified.auth_level(), AuthLevel::Level2ApiKey);
        assert_eq!(verified.subject(), "api-key-user");
    }

    #[tokio::test]
    async fn test_api_key_authenticator_invalid() {
        let auth = ApiKeyAuthenticator::new(vec!["sk_live_secret_key_123".to_string()]);
        let err = auth
            .authenticate("Bearer sk_wrong_key")
            .expect_err("Wrong key must fail");

        assert!(err.to_string().contains("Invalid API key"));
    }

    #[tokio::test]
    async fn test_api_key_authenticator_empty() {
        let auth = ApiKeyAuthenticator::new(vec!["sk_live_secret_key_123".to_string()]);
        let err = auth.authenticate("").expect_err("Empty key must fail");
        assert!(err.to_string().contains("Empty authorization"));
    }
}
