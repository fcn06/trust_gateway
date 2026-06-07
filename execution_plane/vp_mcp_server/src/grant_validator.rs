use jwt_simple::prelude::*;
use trust_core::grant::ExecutionGrant;

/// Validates ExecutionGrant JWTs from the trust_gateway.
pub struct GrantValidator {
    ed25519_key: Option<Ed25519PublicKey>,
    hmac_key: Option<HS256Key>,
}

impl GrantValidator {
    /// Create a validator with Ed25519 public key only (recommended).
    pub fn from_ed25519_pem(pem: &str) -> anyhow::Result<Self> {
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
    pub fn dual(ed25519_pem: &str, hmac_secret: &str) -> anyhow::Result<Self> {
        let ed_key = Ed25519PublicKey::from_pem(ed25519_pem)?;
        Ok(Self {
            ed25519_key: Some(ed_key),
            hmac_key: Some(HS256Key::from_bytes(hmac_secret.as_bytes())),
        })
    }

    /// Validate with mandatory input_hash argument binding (SEC-2).
    pub fn validate_with_args(
        &self,
        token: &str,
        requested_tool: &str,
        arguments: Option<&serde_json::Value>,
    ) -> Result<ExecutionGrant, String> {
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };

        // Try Ed25519 first (preferred)
        if let Some(ref ed_key) = self.ed25519_key {
            match ed_key.verify_token::<ExecutionGrant>(token, Some(options.clone())) {
                Ok(claims) => {
                    let now = chrono::Utc::now().timestamp();
                    if claims.custom.expires_at < now {
                        return Err("ExecutionGrant has expired".to_string());
                    }
                    if claims.custom.allowed_action != requested_tool {
                        return Err(format!(
                            "Grant mismatch: grant allows '{}' but '{}' was requested",
                            claims.custom.allowed_action, requested_tool
                        ));
                    }
                    // SEC-2: input_hash binding is mandatory
                    if let Some(args) = arguments {
                        let actual_hash = trust_core::canonical_json::canonical_hash(args);
                        if claims.custom.input_hash != actual_hash {
                            return Err("Grant input_hash mismatch: arguments tampered".to_string());
                        }
                    }
                    return Ok(claims.custom);
                }
                Err(e) => {
                    if self.hmac_key.is_some() {
                        tracing::debug!("Ed25519 verification failed, trying HMAC: {}", e);
                    } else {
                        return Err(format!("Grant validation failed (Ed25519): {}", e));
                    }
                }
            }
        }

        // Fall back to HMAC (legacy)
        if let Some(ref hmac_key) = self.hmac_key {
            tracing::warn!("⚠️ Grant validation fell back to HMAC. HMAC is deprecated and for development only (SEC-1).");
            let claims = hmac_key
                .verify_token::<ExecutionGrant>(token, Some(options))
                .map_err(|e| format!("Grant validation failed (HMAC): {}", e))?;

            let now = chrono::Utc::now().timestamp();
            if claims.custom.expires_at < now {
                return Err("ExecutionGrant has expired".to_string());
            }
            if claims.custom.allowed_action != requested_tool {
                return Err(format!(
                    "Grant mismatch: grant allows '{}' but '{}' was requested",
                    claims.custom.allowed_action, requested_tool
                ));
            }
            // SEC-2: input_hash binding is mandatory
            if let Some(args) = arguments {
                let actual_hash = trust_core::canonical_json::canonical_hash(args);
                if claims.custom.input_hash != actual_hash {
                    return Err("Grant input_hash mismatch: arguments tampered".to_string());
                }
            }
            return Ok(claims.custom);
        }

        Err("No verification key configured — cannot validate grant".to_string())
    }
}
