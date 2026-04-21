// ─────────────────────────────────────────────────────────────
// In-Memory Nonce Store — JTI Replay Prevention
//
// A consume-once store for ExecutionGrant JTI values. Each grant_id
// may only be presented once within its TTL window. Prevents replay
// attacks where an intercepted grant JWT is re-used to trigger
// duplicate execution of the same action.
//
// The 30s grant TTL means the store never grows beyond
// max_concurrent_grants entries. At ~100 bytes per entry and
// a realistic throughput of 100 grants/sec, peak memory is ~3KB.
//
// For horizontally scaled executors, swap this implementation
// for a JetStreamNonceStore backed by a NATS KV bucket.
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use trust_core::errors::NonceError;

/// In-memory JTI nonce store with TTL-based auto-expiry.
///
/// Uses a HashMap protected by RwLock. Expired entries are pruned
/// lazily on each `consume()` call when the map exceeds a threshold.
pub struct InMemoryNonceStore {
    seen: RwLock<HashMap<String, Instant>>,
    /// Sweep expired entries every N consume() calls.
    sweep_threshold: usize,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            sweep_threshold: 100,
        }
    }
}

#[async_trait::async_trait]
impl trust_core::traits::NonceStore for InMemoryNonceStore {
    async fn consume(&self, jti: &str, ttl: Duration) -> Result<(), NonceError> {
        let now = Instant::now();
        let mut map = self.seen.write().await;

        // Lazy sweep: remove expired entries when map grows past threshold
        if map.len() >= self.sweep_threshold {
            map.retain(|_, inserted| now.duration_since(*inserted) < ttl);
        }

        // Check if already consumed (and not expired)
        if let Some(inserted) = map.get(jti) {
            if now.duration_since(*inserted) < ttl {
                return Err(NonceError::AlreadyConsumed {
                    jti: jti.to_string(),
                });
            }
            // Entry expired — allow re-use (though JWT also expired)
        }

        map.insert(jti.to_string(), now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_core::traits::NonceStore;

    #[tokio::test]
    async fn test_first_consume_succeeds() {
        let store = InMemoryNonceStore::new();
        let result = store.consume("grant-1", Duration::from_secs(30)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_second_consume_fails() {
        let store = InMemoryNonceStore::new();
        store.consume("grant-1", Duration::from_secs(30)).await.unwrap();
        let result = store.consume("grant-1", Duration::from_secs(30)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            NonceError::AlreadyConsumed { jti } => assert_eq!(jti, "grant-1"),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_different_jtis_succeed() {
        let store = InMemoryNonceStore::new();
        store.consume("grant-1", Duration::from_secs(30)).await.unwrap();
        let result = store.consume("grant-2", Duration::from_secs(30)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_expired_entry_allows_reuse() {
        let store = InMemoryNonceStore::new();
        // Use a very short TTL
        store.consume("grant-1", Duration::from_millis(10)).await.unwrap();
        // Wait for it to expire
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Should succeed — entry expired
        let result = store.consume("grant-1", Duration::from_millis(10)).await;
        assert!(result.is_ok());
    }
}
