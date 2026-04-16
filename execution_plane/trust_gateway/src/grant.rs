// ─────────────────────────────────────────────────────────────
// ExecutionGrant JWT issuer
//
// Issues narrow, action-specific JWTs using HMAC-SHA256.
// These replace broad session tokens for connector execution.
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use jwt_simple::prelude::*;
use trust_core::action::ActionRequest;
use trust_core::grant::{ExecutionGrant, GrantClearance, SignedGrant};

/// Issues ExecutionGrant JWTs using HMAC-SHA256.
///
/// The same signing key must be shared with connectors so they
/// can validate the grant before executing.
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

// ── Trait bridge ────────────────────────────────────────────
// Allows GatewayState to hold Arc<dyn GrantIssuer> and dispatch
// to HmacGrantIssuer without knowing the concrete type.

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
