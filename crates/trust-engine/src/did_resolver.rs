use crate::traits::EngineError;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use trust_sdk::did::{
    did_web_to_https_url_with_options, extract_did_twin_ed25519_pubkey, DidDocument,
};

#[async_trait]
pub trait DidResolver: Send + Sync {
    async fn resolve_ed25519_key(&self, did: &str) -> Result<[u8; 32], EngineError>;
}

#[derive(Debug, Clone)]
struct CachedKey {
    key: [u8; 32],
    expires_at: i64,
}

#[derive(Clone)]
pub struct CachedDidResolver {
    cache: Arc<DashMap<String, CachedKey>>,
    client: reqwest::Client,
    ttl_secs: i64,
    allow_localhost: bool,
}

impl Default for CachedDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedDidResolver {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Reqwest client for DID resolver must build");

        Self {
            cache: Arc::new(DashMap::new()),
            client,
            ttl_secs: 3600,
            allow_localhost: false,
        }
    }

    pub fn with_ttl(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    pub fn with_allow_localhost(mut self, allow: bool) -> Self {
        self.allow_localhost = allow;
        self
    }

    /// Pre-populate cache for tests or known offline DIDs
    pub fn insert_cached_key(&self, did: &str, key: [u8; 32], ttl_secs: i64) {
        let norm_key = did.replace(':', "_");
        let now = chrono::Utc::now().timestamp();
        self.cache.insert(
            norm_key,
            CachedKey {
                key,
                expires_at: now + ttl_secs,
            },
        );
    }
}

#[async_trait]
impl DidResolver for CachedDidResolver {
    async fn resolve_ed25519_key(&self, did: &str) -> Result<[u8; 32], EngineError> {
        // 1. did:twin is resolved offline immediately
        if did.starts_with("did:twin:") {
            return extract_did_twin_ed25519_pubkey(did)
                .map_err(|e| EngineError::AuthError(format!("Invalid did:twin format: {e}")));
        }

        // 2. did:key is resolved offline immediately
        if did.starts_with("did:key:") {
            return trust_sdk::did::extract_did_key_ed25519_pubkey(did)
                .map_err(|e| EngineError::AuthError(format!("Invalid did:key format: {e}")));
        }

        // 3. did:web resolution with in-memory TTL caching
        if did.starts_with("did:web:") {
            let norm_key = did.replace(':', "_");
            let now = chrono::Utc::now().timestamp();

            if let Some(entry) = self.cache.get(&norm_key) {
                if now < entry.expires_at {
                    return Ok(entry.key);
                }
            }

            let url =
                did_web_to_https_url_with_options(did, self.allow_localhost).map_err(|e| {
                    EngineError::AuthError(format!("Invalid did:web url conversion: {e}"))
                })?;

            let res = self.client.get(&url).send().await.map_err(|e| {
                EngineError::AuthError(format!("Failed to fetch did:web at {url}: {e}"))
            })?;

            if !res.status().is_success() {
                return Err(EngineError::AuthError(format!(
                    "did:web endpoint {url} returned HTTP status {}",
                    res.status()
                )));
            }

            let body_bytes = res
                .bytes()
                .await
                .map_err(|e| EngineError::AuthError(format!("Failed to read did:web body: {e}")))?;

            let doc: DidDocument = serde_json::from_slice(&body_bytes).map_err(|e| {
                EngineError::AuthError(format!("Failed to parse W3C DidDocument: {e}"))
            })?;

            let pubkey = doc.find_ed25519_pubkey().map_err(|e| {
                EngineError::AuthError(format!("No valid Ed25519 key found in DidDocument: {e}"))
            })?;

            self.cache.insert(
                norm_key,
                CachedKey {
                    key: pubkey,
                    expires_at: now + self.ttl_secs,
                },
            );

            return Ok(pubkey);
        }

        Err(EngineError::AuthError(format!(
            "Unsupported DID method in '{did}' (only did:twin and did:web are supported)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_sdk::did::create_did_twin_from_seed;

    #[tokio::test]
    async fn test_resolve_did_twin_offline() {
        let resolver = CachedDidResolver::new();
        let identity = create_did_twin_from_seed([44u8; 32]);

        let resolved = resolver.resolve_ed25519_key(&identity.did).await.unwrap();
        assert_eq!(resolved, identity.public_key);
    }

    #[tokio::test]
    async fn test_resolve_did_key_offline() {
        let resolver = CachedDidResolver::new();
        let identity = trust_sdk::did::create_did_key_from_seed([55u8; 32]);

        let resolved = resolver.resolve_ed25519_key(&identity.did).await.unwrap();
        assert_eq!(resolved, identity.public_key);
    }

    #[tokio::test]
    async fn test_cached_key_lookup() {
        let resolver = CachedDidResolver::new();
        let key = [88u8; 32];
        let did = "did:web:example.com";

        resolver.insert_cached_key(did, key, 3600);
        let resolved = resolver.resolve_ed25519_key(did).await.unwrap();
        assert_eq!(resolved, key);
    }
}
