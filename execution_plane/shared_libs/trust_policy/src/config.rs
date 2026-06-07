// ─────────────────────────────────────────────────────────────
// Policy configuration helpers
// ─────────────────────────────────────────────────────────────

use crate::rules::PolicySet;

/// Higher-level policy configuration container.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// The loaded policy set.
    pub policy_set: PolicySet,
    /// Path to the policy file (for reloading).
    pub file_path: Option<String>,
}

impl PolicyConfig {
    /// Load from a TOML file.
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let policy_set = PolicySet::from_file(path)?;
        Ok(Self {
            policy_set,
            file_path: Some(path.to_string()),
        })
    }

    /// Reload the policy from disk (if loaded from a file).
    pub fn reload(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref path) = self.file_path {
            self.policy_set = PolicySet::from_file(path)?;
            Ok(())
        } else {
            Err("No file path configured for reload".into())
        }
    }
}
