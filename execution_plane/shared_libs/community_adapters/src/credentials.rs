// ─────────────────────────────────────────────────────────────
// EnvCredentialProvider — Community edition credential provider.
//
// Reads secrets from environment variables only. No external
// vault, KMS, or secret manager integration.
// ─────────────────────────────────────────────────────────────

use async_trait::async_trait;
use trust_core::ports::CredentialProvider;

/// Community edition credential provider — reads from env vars.
pub struct EnvCredentialProvider;

impl EnvCredentialProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnvCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialProvider for EnvCredentialProvider {
    async fn get_secret(&self, key: &str) -> anyhow::Result<Option<String>> {
        match std::env::var(key) {
            Ok(val) if !val.is_empty() => Ok(Some(val)),
            Ok(_) => Ok(None), // Empty string treated as absent
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to read env var '{}': {}", key, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_env_provider_missing_key() {
        let provider = EnvCredentialProvider::new();
        let result = provider
            .get_secret("COMMUNITY_ADAPTERS_TEST_NONEXISTENT_KEY_12345")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EnvCredentialProvider>();
    }
}
