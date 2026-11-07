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
    async fn resolve_service_endpoint(
        &self,
        did: &str,
        service_type: &str,
    ) -> Result<String, EngineError> {
        let _ = (did, service_type);
        Err(EngineError::AuthError(
            "Service endpoint resolution not implemented".to_string(),
        ))
    }
}

#[derive(Debug, Clone)]
struct CachedKey {
    key: [u8; 32],
    service_endpoint: Option<String>,
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

    fn verify_did_web_url_ssrf(&self, url_str: &str) -> Result<(), EngineError> {
        if self.allow_localhost {
            return Ok(());
        }
        let parsed = reqwest::Url::parse(url_str)
            .map_err(|e| EngineError::AuthError(format!("Invalid did:web URL: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| EngineError::AuthError("did:web URL missing host".to_string()))?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let is_private_or_local = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_unspecified()
                }
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
            };
            if is_private_or_local {
                return Err(EngineError::AuthError(format!(
                    "SSRF protection blocked private/loopback IP in did:web resolution: {ip}"
                )));
            }
        }
        Ok(())
    }

    /// Pre-populate cache for tests or known offline DIDs
    pub fn insert_cached_key(&self, did: &str, key: [u8; 32], ttl_secs: i64) {
        let norm_key = did.replace(':', "_");
        let now = chrono::Utc::now().timestamp();
        if let Some(mut entry) = self.cache.get_mut(&norm_key) {
            entry.key = key;
            entry.expires_at = now + ttl_secs;
        } else {
            self.cache.insert(
                norm_key,
                CachedKey {
                    key,
                    service_endpoint: None,
                    expires_at: now + ttl_secs,
                },
            );
        }
    }

    /// Pre-populate cached service endpoint for tests
    pub fn insert_cached_endpoint(&self, did: &str, endpoint: String, ttl_secs: i64) {
        let norm_key = did.replace(':', "_");
        let now = chrono::Utc::now().timestamp();
        if let Some(mut entry) = self.cache.get_mut(&norm_key) {
            entry.service_endpoint = Some(endpoint);
            entry.expires_at = now + ttl_secs;
        } else {
            self.cache.insert(
                norm_key,
                CachedKey {
                    key: [0u8; 32],
                    service_endpoint: Some(endpoint),
                    expires_at: now + ttl_secs,
                },
            );
        }
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
                if now < entry.expires_at && entry.key != [0u8; 32] {
                    return Ok(entry.key);
                }
            }

            let url =
                did_web_to_https_url_with_options(did, self.allow_localhost).map_err(|e| {
                    EngineError::AuthError(format!("Invalid did:web url conversion: {e}"))
                })?;
            self.verify_did_web_url_ssrf(&url)?;

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

            let ep = doc
                .find_service_endpoint("SkillExecutionService")
                .map(|s| s.to_string());

            self.cache.insert(
                norm_key,
                CachedKey {
                    key: pubkey,
                    service_endpoint: ep,
                    expires_at: now + self.ttl_secs,
                },
            );

            return Ok(pubkey);
        }

        Err(EngineError::AuthError(format!(
            "Unsupported DID method: {did}"
        )))
    }

    async fn resolve_service_endpoint(
        &self,
        did: &str,
        service_type: &str,
    ) -> Result<String, EngineError> {
        if did.starts_with("did:web:") {
            let norm_key = did.replace(':', "_");
            let now = chrono::Utc::now().timestamp();

            if let Some(entry) = self.cache.get(&norm_key) {
                if now < entry.expires_at {
                    if let Some(ref ep) = entry.service_endpoint {
                        return Ok(ep.clone());
                    }
                }
            }

            let url =
                did_web_to_https_url_with_options(did, self.allow_localhost).map_err(|e| {
                    EngineError::AuthError(format!("Invalid did:web url conversion: {e}"))
                })?;
            self.verify_did_web_url_ssrf(&url)?;

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

            let ep = doc
                .find_service_endpoint(service_type)
                .ok_or_else(|| {
                    EngineError::SkillValidation(format!(
                        "No service endpoint of type '{service_type}' found in DID document for {did}"
                    ))
                })?
                .to_string();

            let pubkey = doc.find_ed25519_pubkey().unwrap_or([0u8; 32]);

            self.cache.insert(
                norm_key,
                CachedKey {
                    key: pubkey,
                    service_endpoint: Some(ep.clone()),
                    expires_at: now + self.ttl_secs,
                },
            );

            return Ok(ep);
        }

        Err(EngineError::AuthError(format!(
            "Only did:web supports service endpoint discovery, got: {did}"
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
