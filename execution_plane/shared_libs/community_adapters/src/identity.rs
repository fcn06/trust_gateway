// ─────────────────────────────────────────────────────────────
// NoopExternalIdentityResolver — Community edition identity resolver.
//
// Always returns Ok(None). The community edition does not have
// external identity sources (OAuth2, VP, etc.).
// ─────────────────────────────────────────────────────────────

use async_trait::async_trait;
use trust_core::ports::ExternalIdentityResolver;
use trust_core::ports_dto::ResolvedIdentity;

/// Community edition identity resolver — always returns None.
pub struct NoopExternalIdentityResolver;

impl NoopExternalIdentityResolver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopExternalIdentityResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ExternalIdentityResolver for NoopExternalIdentityResolver {
    async fn resolve(&self, _subject: &str) -> anyhow::Result<Option<ResolvedIdentity>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_resolver_returns_none() {
        let resolver = NoopExternalIdentityResolver::new();
        let result = resolver.resolve("did:example:123").await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resolver_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopExternalIdentityResolver>();
    }
}
