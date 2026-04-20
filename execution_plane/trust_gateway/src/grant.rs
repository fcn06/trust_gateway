// ─────────────────────────────────────────────────────────────
// ExecutionGrant JWT issuer
//
// WS1: Supports both Ed25519 asymmetric signing (recommended)
// and HMAC-SHA256 (legacy/backward-compat).
//
// Ed25519 separates signer (gateway, holds private key) from
// verifier (executor, holds public key only). This prevents
// executors from minting their own grants.
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use jwt_simple::prelude::*;
use trust_core::action::ActionRequest;
use trust_core::grant::{ExecutionGrant, GrantClearance, SignedGrant};

// ── Ed25519 Grant Issuer (WS1: Asymmetric) ─────────────────

/// Issues ExecutionGrant JWTs using Ed25519 asymmetric signing.
///
/// The gateway holds the private key (signer). Executors hold
/// only the public key (verifier) and cannot mint grants.
pub struct Ed25519GrantIssuer {
    key_pair: Ed25519KeyPair,
    kid: String,
}

impl Ed25519GrantIssuer {
    /// Create from a PEM-encoded Ed25519 private key.
    pub fn from_pem(pem: &str, kid: String) -> Result<Self> {
        let key_pair = Ed25519KeyPair::from_pem(pem)?;
        Ok(Self { key_pair, kid })
    }

    /// Generate a new random Ed25519 key pair (for dev/testing).
    pub fn generate(kid: String) -> Self {
        let key_pair = Ed25519KeyPair::generate();
        Self { key_pair, kid }
    }

    /// Export the public key as PEM (for distributing to executors).
    pub fn public_key_pem(&self) -> String {
        self.key_pair.public_key().to_pem()
    }

    /// Export the key pair as PEM (for persistence).
    pub fn key_pair_pem(&self) -> String {
        self.key_pair.to_pem()
    }

    /// Get the Key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Issue a short-lived ExecutionGrant for a specific action.
    pub fn issue(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> Result<SignedGrant> {
        let grant_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;

        let grant = ExecutionGrant {
            grant_id: grant_id.clone(),
            action_id: req.action_id.clone(),
            tenant_id: req.tenant_id.clone(),
            owner_did: req.actor.owner_did.clone(),
            requester_did: req.actor.requester_did.clone(),
            allowed_action: req.action.name.clone(),
            clearance,
            expires_at,
            kid: Some(self.kid.clone()),
        };

        // Build JWT claims with kid in the header
        let claims = Claims::with_custom_claims(
            grant.clone(),
            Duration::from_secs(ttl.as_secs()),
        )
        .with_issuer("trust_gateway")
        .with_subject(&req.action_id)
        .with_jwt_id(&grant_id);

        let token = self.key_pair.sign(claims)?;

        Ok(SignedGrant {
            token,
            claims: grant,
        })
    }
}

impl trust_core::traits::GrantIssuer for Ed25519GrantIssuer {
    fn issue_execution_grant(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> std::result::Result<SignedGrant, trust_core::errors::GrantError> {
        self.issue(req, clearance, ttl)
            .map_err(|e| trust_core::errors::GrantError::SigningFailed(e.to_string()))
    }
}

// ── HMAC Grant Issuer (Legacy/Backward-Compat) ─────────────

/// Issues ExecutionGrant JWTs using HMAC-SHA256.
///
/// Kept for backward compatibility. The same signing key must be
/// shared with connectors so they can validate the grant.
///
/// **Deprecated**: Use `Ed25519GrantIssuer` for new deployments.
pub struct HmacGrantIssuer {
    key: HS256Key,
}

impl HmacGrantIssuer {
    pub fn new(secret: &str) -> Self {
        Self {
            key: HS256Key::from_bytes(secret.as_bytes()),
        }
    }

    /// Issue a short-lived ExecutionGrant for a specific action.
    pub fn issue(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> Result<SignedGrant> {
        let grant_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;

        let grant = ExecutionGrant {
            grant_id: grant_id.clone(),
            action_id: req.action_id.clone(),
            tenant_id: req.tenant_id.clone(),
            owner_did: req.actor.owner_did.clone(),
            requester_did: req.actor.requester_did.clone(),
            allowed_action: req.action.name.clone(),
            clearance,
            expires_at,
            kid: None,
        };

        // Build JWT claims
        let claims = Claims::with_custom_claims(
            grant.clone(),
            Duration::from_secs(ttl.as_secs()),
        )
        .with_issuer("trust_gateway")
        .with_subject(&req.action_id)
        .with_jwt_id(&grant_id);

        let token = self.key.authenticate(claims)?;

        Ok(SignedGrant {
            token,
            claims: grant,
        })
    }

    /// Validate an ExecutionGrant JWT and return the claims.
    pub fn validate(&self, token: &str) -> Result<ExecutionGrant> {
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };
        let claims = self.key.verify_token::<ExecutionGrant>(token, Some(options))?;
        Ok(claims.custom)
    }
}

impl trust_core::traits::GrantIssuer for HmacGrantIssuer {
    fn issue_execution_grant(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> std::result::Result<SignedGrant, trust_core::errors::GrantError> {
        self.issue(req, clearance, ttl)
            .map_err(|e| trust_core::errors::GrantError::SigningFailed(e.to_string()))
    }
}
