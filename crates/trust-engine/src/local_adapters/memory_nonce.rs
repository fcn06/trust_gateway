use crate::traits::{EngineError, NonceStore};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct InMemoryNonceStore {
    nonces: Arc<RwLock<HashMap<String, i64>>>,
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl NonceStore for InMemoryNonceStore {
    async fn consume_nonce(
        &self,
        tenant_id: &str,
        jti: &str,
        ttl_secs: u64,
    ) -> Result<(), EngineError> {
        let key = format!("{}_{}", tenant_id, jti);
        let now = chrono::Utc::now().timestamp();
        let mut lock = self.nonces.write().await;

        if let Some(&expires_at) = lock.get(&key) {
            if now < expires_at {
                return Err(EngineError::ReplayDetected(jti.to_string()));
            }
        }

        lock.insert(key, now + ttl_secs as i64);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_replay_rejected_within_ttl() {
        let store = InMemoryNonceStore::new();
        // First consumption succeeds
        assert!(store.consume_nonce("tenant_a", "jti_123", 30).await.is_ok());

        // Second consumption within TTL must be rejected!
        let err = store
            .consume_nonce("tenant_a", "jti_123", 30)
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::ReplayDetected(_)));
    }
}
