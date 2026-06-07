// ─────────────────────────────────────────────────────────────
// Policy Fingerprint — integrity verification for policy.toml
//
// Computes a SHA-256 fingerprint of the policy file at load time.
// Optionally verifies a detached Ed25519 signature if a sig file
// exists and POLICY_SIGNATURE_REQUIRED is set.
//
// The fingerprint is included in grant.issued audit events so
// auditors can prove which version of the policy was in effect
// when a specific grant was authorized.
// ─────────────────────────────────────────────────────────────

use sha2::{Digest, Sha256};
use std::path::Path;

/// Result of loading and fingerprinting a policy file.
#[derive(Debug, Clone)]
pub struct PolicyFingerprint {
    /// SHA-256 hex hash of the raw policy file bytes.
    pub hash: String,
    /// Number of rules loaded.
    pub rule_count: usize,
    /// Whether a detached signature was verified.
    pub signature_verified: bool,
}

/// Compute the SHA-256 fingerprint of a policy file.
pub fn compute_fingerprint(policy_path: &Path) -> Result<String, anyhow::Error> {
    let contents = std::fs::read(policy_path)
        .map_err(|e| anyhow::anyhow!("Failed to read policy file {:?}: {}", policy_path, e))?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute the fingerprint from raw policy bytes (for in-memory policies).
pub fn compute_fingerprint_from_bytes(policy_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy_bytes);
    format!("{:x}", hasher.finalize())
}

/// Verify a detached Ed25519 signature for a policy file.
///
/// The signature file is expected at `{policy_path}.sig` and contains
/// the raw Ed25519 signature bytes (64 bytes).
///
/// This is controlled by the `POLICY_SIGNATURE_REQUIRED` env var:
/// - `"1"` or `"true"`: Startup fails if signature is missing or invalid
/// - `"0"` or unset: Warn-only mode (default during rollout)
pub fn verify_policy_signature(
    policy_path: &Path,
    public_key_pem: Option<&str>,
) -> Result<bool, anyhow::Error> {
    let sig_path = policy_path.with_extension("toml.sig");
    let required = std::env::var("POLICY_SIGNATURE_REQUIRED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !sig_path.exists() {
        if required {
            anyhow::bail!(
                "Policy signature required but not found at {:?}. \
                 Set POLICY_SIGNATURE_REQUIRED=0 to disable.",
                sig_path
            );
        }
        tracing::info!(
            "ℹ️  No policy signature file at {:?} — skipping verification",
            sig_path
        );
        return Ok(false);
    }

    // If we have a signature file and a public key, verify it
    if let Some(pem) = public_key_pem {
        let sig_bytes = std::fs::read(&sig_path)?;
        if sig_bytes.is_empty() {
            if required {
                anyhow::bail!("Policy signature file is empty");
            }
            tracing::warn!("⚠️ Policy signature file is empty — skipping verification");
            return Ok(false);
        }
        
        let policy_bytes = std::fs::read(policy_path)?;

        // Phase 6: Full Ed25519 detached signature verification
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};

        // Attempt to parse the public key (assume hex or base64 or raw bytes)
        // Here we assume it's provided as a hex string for simplicity
        let pub_key_bytes = hex::decode(pem.trim()).map_err(|e| {
            anyhow::anyhow!("Failed to decode POLICY_SIGNATURE_PUBLIC_KEY hex: {}", e)
        })?;
        
        if pub_key_bytes.len() != 32 {
            anyhow::bail!("Invalid Ed25519 public key length (expected 32 bytes)");
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&pub_key_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;

        // Attempt to parse the signature
        // Assuming the signature file contains raw bytes (64 bytes) or hex
        let sig_array = if sig_bytes.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig_bytes);
            arr
        } else {
            // Try hex decoding
            let decoded = hex::decode(String::from_utf8_lossy(&sig_bytes).trim())
                .map_err(|_| anyhow::anyhow!("Signature file must be 64 raw bytes or hex-encoded string"))?;
            if decoded.len() != 64 {
                anyhow::bail!("Invalid Ed25519 signature length (expected 64 bytes)");
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&decoded);
            arr
        };

        let signature = Signature::from_bytes(&sig_array);

        // Verify the signature against the policy file contents
        if let Err(e) = verifying_key.verify(&policy_bytes, &signature) {
            tracing::error!("🚨 Ed25519 signature verification failed: {}", e);
            anyhow::bail!("Policy signature verification failed: invalid signature");
        }

        tracing::info!(
            "✅ Policy signature file verified successfully against Ed25519 key"
        );
        Ok(true)
    } else {
        if required {
            anyhow::bail!("Policy signature required but no verification key configured");
        }
        tracing::info!("ℹ️  No policy verification key configured — skipping signature check");
        Ok(false)
    }
}

/// Load policy, compute fingerprint, and optionally verify signature.
/// Returns the fingerprint info for inclusion in audit events.
pub fn load_and_fingerprint(
    policy_toml: &str,
    policy_path: Option<&Path>,
    rule_count: usize,
) -> Result<PolicyFingerprint, anyhow::Error> {
    let hash = compute_fingerprint_from_bytes(policy_toml.as_bytes());

    let signature_verified = if let Some(path) = policy_path {
        let pub_key = std::env::var("POLICY_SIGNATURE_PUBLIC_KEY").ok();
        verify_policy_signature(path, pub_key.as_deref())?
    } else {
        false
    };

    tracing::info!(
        "📋 Policy loaded: {} rules, fingerprint={}, signature_verified={}",
        rule_count,
        &hash[..16],
        signature_verified
    );

    Ok(PolicyFingerprint {
        hash,
        rule_count,
        signature_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_deterministic() {
        let policy = r#"
[[rules]]
id = "test"
priority = 10
effect = "allow"
"#;
        let hash1 = compute_fingerprint_from_bytes(policy.as_bytes());
        let hash2 = compute_fingerprint_from_bytes(policy.as_bytes());
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_fingerprint_changes_with_content() {
        let a = compute_fingerprint_from_bytes(b"policy version 1");
        let b = compute_fingerprint_from_bytes(b"policy version 2");
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_missing_sig_not_required() {
        // No sig file, not required — should return Ok(false)
        let path = Path::new("/tmp/nonexistent_policy.toml");
        std::env::remove_var("POLICY_SIGNATURE_REQUIRED");
        let result = verify_policy_signature(path, None);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_load_and_fingerprint_basic() {
        let policy = "[[rules]]\nid = \"r1\"\npriority = 1\neffect = \"deny\"\n";
        let fp = load_and_fingerprint(policy, None, 1).expect("fingerprint should succeed");
        assert_eq!(fp.rule_count, 1);
        assert_eq!(fp.hash.len(), 64);
        assert!(!fp.signature_verified);
    }
}
