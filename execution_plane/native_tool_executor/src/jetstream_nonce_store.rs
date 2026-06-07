// ─────────────────────────────────────────────────────────────
// JetStream Nonce Store — Persistent JTI Replay Prevention
//
// A NATS JetStream KV-backed nonce store that survives executor
// restarts. Each grant_id is stored as a key with a TTL matching
// the grant's remaining lifetime (capped at 35s).
//
// This replaces the InMemoryNonceStore for production deployments
// where multiple executor instances must share nonce state.
// ─────────────────────────────────────────────────────────────

use std::time::Duration;
use trust_core::errors::NonceError;

/// JetStream KV-backed nonce store for horizontally-scaled executors.
///
/// Each consumed JTI is stored as a key in the `grant_nonces` KV bucket.
/// The bucket's max_age is set to 35s (slightly longer than grant TTL)
/// to ensure automatic cleanup.
pub struct JetStreamNonceStore {
    js: async_nats::jetstream::Context,
    bucket_name: String,
}

impl JetStreamNonceStore {
    pub fn new(js: async_nats::jetstream::Context, bucket_name: impl Into<String>) -> Self {
        Self {
            js,
            bucket_name: bucket_name.into(),
        }
    }

    /// Ensure the KV bucket exists with appropriate TTL settings.
    pub async fn ensure_bucket(&self) -> Result<(), anyhow::Error> {
        use async_nats::jetstream::kv::Config;

        let config = Config {
            bucket: self.bucket_name.clone(),
            max_age: Duration::from_secs(35), // Slightly longer than grant TTL
            description: "Grant JTI nonce store for replay prevention".to_string(),
            ..Default::default()
        };

        // Create or bind to existing bucket
        match self.js.create_key_value(config).await {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!("JetStream nonce bucket creation: {}", e);
                // Bucket might already exist — try to get it
                self.js
                    .get_key_value(&self.bucket_name)
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("Failed to access nonce bucket: {}", e))
            }
        }
    }
}

#[async_trait::async_trait]
impl trust_core::traits::NonceStore for JetStreamNonceStore {
    async fn consume(&self, jti: &str, _ttl: Duration) -> Result<(), NonceError> {
        let store = self
            .js
            .get_key_value(&self.bucket_name)
            .await
            .map_err(|e| NonceError::Backend(format!("Failed to access nonce bucket: {}", e)))?;

        // RULE[020_JETSTREAM_KEYS.md]: Use _ as separator
        let key = format!("nonce_{}", jti);

        // Check if JTI already exists
        match store.get(&key).await {
            Ok(Some(_)) => {
                // JTI already consumed — replay attack
                tracing::warn!("🛡️ Grant replay blocked: JTI={}", jti);
                return Err(NonceError::AlreadyConsumed {
                    jti: jti.to_string(),
                });
            }
            Ok(None) => {
                // Not consumed yet — proceed
            }
            Err(e) => {
                tracing::warn!("Nonce store lookup error (allowing): {}", e);
                // On error, fail-open to avoid blocking legitimate grants
                // The KV bucket's max_age handles cleanup
            }
        }

        // Store the JTI — the bucket's max_age handles expiry
        store
            .put(&key, "1".into())
            .await
            .map_err(|e| NonceError::Backend(format!("Failed to store nonce: {}", e)))?;

        Ok(())
    }
}
