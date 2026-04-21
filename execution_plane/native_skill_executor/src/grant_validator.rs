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
//
// JTI Replay Prevention: When a NonceStore is configured, the
// validator enforces consume-once semantics on the grant_id (JTI).
// A replayed grant is rejected even if its signature and expiry
// are still valid.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use anyhow::Result;
use jwt_simple::prelude::*;
use trust_core::grant::ExecutionGrant;

/// Validates ExecutionGrant JWTs from the trust_gateway.
///
/// WS1: Supports dual-mode verification:
/// - Ed25519 (asymmetric) — executor holds only the public key
/// - HMAC (symmetric, legacy) — executor shares the secret
///
/// Optionally enforces JTI replay prevention via a `NonceStore`.
pub struct GrantValidator {
    ed25519_key: Option<Ed25519PublicKey>,
    hmac_key: Option<HS256Key>,
    nonce_store: Option<Arc<dyn trust_core::traits::NonceStore>>,
}

impl GrantValidator {
    /// Create a validator with Ed25519 public key only (recommended).
    pub fn from_ed25519_pem(pem: &str) -> Result<Self> {
        let key = Ed25519PublicKey::from_pem(pem)?;
        Ok(Self {
            ed25519_key: Some(key),
            hmac_key: None,
            nonce_store: None,
        })
    }

    /// Create a validator with HMAC shared secret (legacy).
    pub fn from_hmac_secret(secret: &str) -> Self {
        Self {
            ed25519_key: None,
            hmac_key: Some(HS256Key::from_bytes(secret.as_bytes())),
            nonce_store: None,
        }
    }

    /// Create a dual-mode validator that accepts both algorithms.
    pub fn dual(ed25519_pem: &str, hmac_secret: &str) -> Result<Self> {
        let ed_key = Ed25519PublicKey::from_pem(ed25519_pem)?;
        Ok(Self {
            ed25519_key: Some(ed_key),
            hmac_key: Some(HS256Key::from_bytes(hmac_secret.as_bytes())),
            nonce_store: None,
        })
    }

    /// Attach a nonce store for JTI replay prevention.
    ///
    /// When set, each grant_id may only be validated once within the
    /// grant's remaining TTL. A second presentation of the same JTI
    /// is rejected with a replay error.
    pub fn with_nonce_store(mut self, store: Arc<dyn trust_core::traits::NonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
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
    /// - JTI has not been consumed before (if NonceStore is configured)
    pub async fn validate(&self, token: &str) -> Result<ExecutionGrant> {
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
                    // JTI replay prevention
                    self.check_nonce(&claims.custom).await?;
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

            // JTI replay prevention
            self.check_nonce(&claims.custom).await?;

            return Ok(claims.custom);
        }

        anyhow::bail!("No verification key configured — cannot validate grant")
    }

    /// Internal: check grant_id against the nonce store (if configured).
    async fn check_nonce(&self, grant: &ExecutionGrant) -> Result<()> {
        if let Some(ref store) = self.nonce_store {
            let remaining_ttl = (grant.expires_at - chrono::Utc::now().timestamp()).max(1) as u64;
            let ttl = std::time::Duration::from_secs(remaining_ttl);
            store.consume(&grant.grant_id, ttl).await
                .map_err(|e| anyhow::anyhow!("Grant replay rejected: {}", e))?;
        }
        Ok(())
    }
}
