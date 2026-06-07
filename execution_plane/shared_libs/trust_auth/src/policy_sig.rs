use anyhow::{Context, Result};
use std::path::Path;

/// Information about a verified policy.
#[derive(Debug, Clone)]
pub struct PolicyFingerprint {
    pub hash_sha256: String,
}

/// Verifies a detached Ed25519 signature for a given policy file.
///
/// Phase 4.1: At gateway startup: verify signature, emit `PolicyLoaded` event with fingerprint
pub fn verify_policy_signature(policy_path: &Path, _sig_path: &Path) -> Result<PolicyFingerprint> {
    // In Phase 4 we will fully implement Ed25519 signature verification against the policy.
    // For Phase 2, we just compute the SHA-256 fingerprint of the policy.toml.

    let content = std::fs::read(policy_path).context("Failed to read policy file")?;

    // Compute SHA-256 hash of the policy content
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash_result = hasher.finalize();

    let hash_hex = hex::encode(hash_result);

    Ok(PolicyFingerprint {
        hash_sha256: hash_hex,
    })
}
