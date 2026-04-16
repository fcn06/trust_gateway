// ─────────────────────────────────────────────────────────────
// ExecutionGrant JWT validator
//
// Validates HMAC-signed ExecutionGrant JWTs issued by the
// trust_gateway. Must share the same signing secret.
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use jwt_simple::prelude::*;
use trust_core::grant::ExecutionGrant;

pub struct GrantValidator {
    key: HS256Key,
}

impl GrantValidator {
    pub fn new(secret: &str) -> Self {
        Self {
            key: HS256Key::from_bytes(secret.as_bytes()),
        }
    }

    /// Validate an ExecutionGrant JWT and return the claims.
    ///
    /// Checks:
    /// 1. HMAC signature is valid
    /// 2. Token has not expired
    /// 3. Issuer is "trust_gateway"
    pub fn validate(&self, token: &str) -> Result<ExecutionGrant> {
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };

        let claims = self.key.verify_token::<ExecutionGrant>(token, Some(options))
            .map_err(|e| anyhow::anyhow!("Grant validation failed: {}", e))?;

        // Additional check: ensure the grant hasn't expired
        let now = chrono::Utc::now().timestamp();
        if claims.custom.expires_at < now {
            anyhow::bail!("ExecutionGrant has expired");
        }

        Ok(claims.custom)
    }
}
