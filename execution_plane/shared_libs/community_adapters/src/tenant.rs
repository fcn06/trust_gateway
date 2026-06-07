// ─────────────────────────────────────────────────────────────
// SingleTenantProvider — Community edition tenant provider.
//
// Always returns "local". The community edition is single-tenant.
// ─────────────────────────────────────────────────────────────

use async_trait::async_trait;
use trust_core::ports::TenantProvider;

/// Community edition tenant provider — always returns "local".
pub struct SingleTenantProvider;

impl SingleTenantProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SingleTenantProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TenantProvider for SingleTenantProvider {
    fn current(&self) -> &str {
        "local"
    }

    async fn resolve(&self, _hint: &str) -> anyhow::Result<String> {
        Ok("local".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_single_tenant_always_local() {
        let provider = SingleTenantProvider::new();
        assert_eq!(provider.current(), "local");
        assert_eq!(provider.resolve("anything").await.unwrap(), "local");
        assert_eq!(provider.resolve("").await.unwrap(), "local");
    }

    #[test]
    fn test_provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SingleTenantProvider>();
    }
}
