// ─────────────────────────────────────────────────────────────
// ExecutionGrant JWT validator
//
// WS1: Supports both Ed25519 asymmetric verification (recommended)
// and HMAC-SHA256 (legacy). The validator holds ONLY the public
// key — it cannot mint grants.
//
// The validator auto-detects the algorithm from the JWT header:
//   - "EdDSA" → Ed25519 public key verification
//   - "HS256" → HMAC shared secret verification (legacy)
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use jwt_simple::prelude::*;
use trust_core::grant::ExecutionGrant;

/// Validates ExecutionGrant JWTs from the trust_gateway.
///
/// WS1: Supports dual-mode verification:
/// - Ed25519 (asymmetric) — executor holds only the public key
/// - HMAC (symmetric, legacy) — executor shares the secret
pub struct GrantValidator {
    ed25519_key: Option<Ed25519PublicKey>,
    hmac_key: Option<HS256Key>,
}

impl GrantValidator {
    /// Create a validator with Ed25519 public key only (recommended).
    pub fn from_ed25519_pem(pem: &str) -> Result<Self> {
        let key = Ed25519PublicKey::from_pem(pem)?;
        Ok(Self {
            ed25519_key: Some(key),
            hmac_key: None,
        })
    }

    /// Create a validator with HMAC shared secret (legacy).
    pub fn from_hmac_secret(secret: &str) -> Self {
        Self {
            ed25519_key: None,
            hmac_key: Some(HS256Key::from_bytes(secret.as_bytes())),
        }
    }

    /// Create a dual-mode validator that accepts both algorithms.
    pub fn dual(ed25519_pem: &str, hmac_secret: &str) -> Result<Self> {
        let ed_key = Ed25519PublicKey::from_pem(ed25519_pem)?;
        Ok(Self {
            ed25519_key: Some(ed_key),
            hmac_key: Some(HS256Key::from_bytes(hmac_secret.as_bytes())),
        })
    }

    /// Validate an ExecutionGrant JWT and return the claims.
    ///
    /// Auto-detects the algorithm from the JWT header:
    /// 1. Try Ed25519 if public key is configured
    /// 2. Fall back to HMAC if shared secret is configured
    /// 3. Fail if neither can verify
    ///
    /// Checks:
    /// - Signature is valid (Ed25519 or HMAC)
    /// - Token has not expired
    /// - Issuer is "trust_gateway"
    pub fn validate(&self, token: &str) -> Result<ExecutionGrant> {
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };

        // Try Ed25519 first (preferred)
        if let Some(ref ed_key) = self.ed25519_key {
            match ed_key.verify_token::<ExecutionGrant>(token, Some(options.clone())) {
                Ok(claims) => {
                    // Additional check: ensure the grant hasn't expired
                    let now = chrono::Utc::now().timestamp();
                    if claims.custom.expires_at < now {
                        anyhow::bail!("ExecutionGrant has expired");
                    }
                    return Ok(claims.custom);
                }
                Err(e) => {
                    if self.hmac_key.is_some() {
                        tracing::debug!("Ed25519 verification failed, trying HMAC: {}", e);
                    } else {
                        return Err(anyhow::anyhow!("Grant validation failed (Ed25519): {}", e));
                    }
                }
            }
        }

        // Fall back to HMAC (legacy)
        if let Some(ref hmac_key) = self.hmac_key {
            let claims = hmac_key.verify_token::<ExecutionGrant>(token, Some(options))
                .map_err(|e| anyhow::anyhow!("Grant validation failed (HMAC): {}", e))?;

            // Additional check: ensure the grant hasn't expired
            let now = chrono::Utc::now().timestamp();
            if claims.custom.expires_at < now {
                anyhow::bail!("ExecutionGrant has expired");
            }

            return Ok(claims.custom);
        }

        anyhow::bail!("No verification key configured — cannot validate grant")
    }
}
