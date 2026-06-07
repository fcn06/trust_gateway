// ─────────────────────────────────────────────────────────────
// Unified ExecutionGrant JWT validator
//
// Shared logic for all executors (Connector, Skill, VP).
// Supports Ed25519 asymmetric verification and HMAC fallback.
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use jwt_simple::prelude::*;
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use crate::grant::ExecutionGrant;
use crate::traits::NonceStore;

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut alphabet = [0u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".iter().enumerate() {
        alphabet[c as usize] = i as u8;
    }
    let bytes = input.as_bytes();
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for &b in bytes {
        if b == b'=' { break; }
        let val = alphabet[b as usize];
        if val == 0 && b != b'A' { continue; } // skip invalid chars/whitespace
        buffer = (buffer << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Some(result)
}

fn extract_kid(token: &str) -> Option<String> {
    let first_part = token.split('.').next()?;
    let decoded = base64url_decode(first_part)?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Validates ExecutionGrant JWTs from the Trust Gateway.
///
/// This is the primary gatekeeper for the execution plane. It ensures
/// that any action performed by an executor has been authorized by
/// the gateway's policy engine.
pub struct GrantValidator {
    ed25519_keys: HashMap<String, Ed25519PublicKey>,
    fallback_ed25519_key: Option<Ed25519PublicKey>,
    hmac_key: Option<HS256Key>,
    nonce_store: Option<Arc<dyn NonceStore>>,
}

impl GrantValidator {
    /// Create a new, empty validator.
    pub fn new() -> Self {
        Self {
            ed25519_keys: HashMap::new(),
            fallback_ed25519_key: None,
            hmac_key: None,
            nonce_store: None,
        }
    }

    /// Create a validator with Ed25519 public key only (recommended).
    pub fn from_ed25519_pem(pem: &str) -> Result<Self> {
        let key = Ed25519PublicKey::from_pem(pem.trim())?;
        Ok(Self {
            ed25519_keys: HashMap::new(),
            fallback_ed25519_key: Some(key),
            hmac_key: None,
            nonce_store: None,
        })
    }

    /// Create a validator with HMAC shared secret (legacy).
    pub fn from_hmac_secret(secret: &str) -> Self {
        Self {
            ed25519_keys: HashMap::new(),
            fallback_ed25519_key: None,
            hmac_key: Some(HS256Key::from_bytes(secret.as_bytes())),
            nonce_store: None,
        }
    }

    /// Create a dual-mode validator that accepts both algorithms.
    pub fn dual(ed25519_pem: &str, hmac_secret: &str) -> Result<Self> {
        let ed_key = Ed25519PublicKey::from_pem(ed25519_pem.trim())?;
        Ok(Self {
            ed25519_keys: HashMap::new(),
            fallback_ed25519_key: Some(ed_key),
            hmac_key: Some(HS256Key::from_bytes(hmac_secret.as_bytes())),
            nonce_store: None,
        })
    }

    /// Add an additional Ed25519 public key indexed by `kid` for rotation.
    pub fn with_ed25519_key(mut self, kid: &str, pem: &str) -> Result<Self> {
        let key = Ed25519PublicKey::from_pem(pem.trim())?;
        self.ed25519_keys.insert(kid.to_string(), key);
        Ok(self)
    }

    /// Set a fallback Ed25519 key.
    pub fn with_fallback_ed25519_key(mut self, pem: &str) -> Result<Self> {
        let key = Ed25519PublicKey::from_pem(pem.trim())?;
        self.fallback_ed25519_key = Some(key);
        Ok(self)
    }

    /// Add HMAC key to the validator.
    pub fn with_hmac_key(mut self, secret: &str) -> Self {
        self.hmac_key = Some(HS256Key::from_bytes(secret.as_bytes()));
        self
    }

    /// Check if at least one verification key is configured.
    pub fn has_keys(&self) -> bool {
        !self.ed25519_keys.is_empty() || self.fallback_ed25519_key.is_some() || self.hmac_key.is_some()
    }

    /// Attach a nonce store for JTI replay prevention.
    pub fn with_nonce_store(mut self, store: Arc<dyn NonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// Validate an ExecutionGrant JWT and return the claims.
    ///
    /// REC-3: Enforces `aud = "executor-host"` to prevent session JWT
    /// substitution. A Session JWT (aud = "trust-gateway") presented here
    /// will be rejected outright.
    pub async fn validate(&self, token: &str) -> Result<ExecutionGrant> {
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert("executor-host".to_string());

        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            allowed_audiences: Some(allowed_audiences),
            ..Default::default()
        };

        // Resolve Ed25519 key by kid header
        let kid = extract_kid(token);
        let ed_key = kid.as_ref()
            .and_then(|k| self.ed25519_keys.get(k))
            .or(self.fallback_ed25519_key.as_ref());

        if let Some(key) = ed_key {
            match key.verify_token::<ExecutionGrant>(token, Some(options.clone())) {
                Ok(claims) => {
                    let now = chrono::Utc::now().timestamp();
                    if claims.custom.expires_at < now {
                        anyhow::bail!("ExecutionGrant has expired");
                    }
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
            let claims = hmac_key
                .verify_token::<ExecutionGrant>(token, Some(options))
                .map_err(|e| anyhow::anyhow!("Grant validation failed (HMAC): {}", e))?;

            let now = chrono::Utc::now().timestamp();
            if claims.custom.expires_at < now {
                anyhow::bail!("ExecutionGrant has expired");
            }

            self.check_nonce(&claims.custom).await?;
            return Ok(claims.custom);
        }

        anyhow::bail!("No verification key configured — cannot validate grant")
    }

    /// Validate a grant and additionally verify tool binding and input hash.
    pub async fn validate_bound(
        &self,
        token: &str,
        requested_tool: &str,
        arguments: &serde_json::Value,
    ) -> Result<ExecutionGrant> {
        let grant = self.validate(token).await?;

        // Check tool name binding
        if grant.allowed_action != requested_tool {
            anyhow::bail!(
                "Grant re-targeting blocked: grant authorizes '{}' but '{}' was requested",
                grant.allowed_action,
                requested_tool
            );
        }

        // SEC-2: input_hash binding is mandatory
        let actual_hash = crate::canonical_json::canonical_hash(arguments);
        if grant.input_hash != actual_hash {
            anyhow::bail!(
                "Grant input_hash mismatch: arguments have been tampered with or differ from the approved request"
            );
        }

        Ok(grant)
    }

    async fn check_nonce(&self, grant: &ExecutionGrant) -> Result<()> {
        if let Some(ref store) = self.nonce_store {
            let remaining_ttl = (grant.expires_at - chrono::Utc::now().timestamp()).max(1) as u64;
            let ttl = std::time::Duration::from_secs(remaining_ttl);
            store
                .consume(&grant.grant_id, ttl)
                .await
                .map_err(|e| anyhow::anyhow!("Grant replay rejected: {}", e))?;
        }
        Ok(())
    }
}
