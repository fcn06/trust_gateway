use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Counterparty reputation metrics tracked by the Trust Gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CounterpartyReputation {
    pub did: String,
    pub successful_count: u64,
    pub failed_count: u64,
    pub last_success_at: Option<i64>,
}

/// Helper function to format Jetstream key using `_` as separator (RULE 020).
pub fn format_reputation_key(tenant_id: &str, did: &str) -> String {
    let sanitized_did = did.replace([':', '/', '.'], "_");
    format!("reputation_{}_{}", tenant_id, sanitized_did)
}

#[async_trait]
pub trait ReputationStore: Send + Sync {
    async fn get_reputation(
        &self,
        tenant_id: &str,
        counterparty_did: &str,
    ) -> Result<CounterpartyReputation>;

    async fn record_execution(
        &self,
        tenant_id: &str,
        counterparty_did: &str,
        success: bool,
    ) -> Result<CounterpartyReputation>;
}

/// In-memory implementation of ReputationStore for unit tests and local dev.
pub struct InMemoryReputationStore {
    records: RwLock<HashMap<String, CounterpartyReputation>>,
}

impl InMemoryReputationStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReputationStore for InMemoryReputationStore {
    async fn get_reputation(
        &self,
        tenant_id: &str,
        counterparty_did: &str,
    ) -> Result<CounterpartyReputation> {
        let key = format_reputation_key(tenant_id, counterparty_did);
        let records = self
            .records
            .read()
            .map_err(|e| anyhow::anyhow!("Lock error: {e}"))?;

        Ok(records
            .get(&key)
            .cloned()
            .unwrap_or_else(|| CounterpartyReputation {
                did: counterparty_did.to_string(),
                successful_count: 0,
                failed_count: 0,
                last_success_at: None,
            }))
    }

    async fn record_execution(
        &self,
        tenant_id: &str,
        counterparty_did: &str,
        success: bool,
    ) -> Result<CounterpartyReputation> {
        let key = format_reputation_key(tenant_id, counterparty_did);
        let mut records = self
            .records
            .write()
            .map_err(|e| anyhow::anyhow!("Lock error: {e}"))?;

        let entry = records
            .entry(key)
            .or_insert_with(|| CounterpartyReputation {
                did: counterparty_did.to_string(),
                successful_count: 0,
                failed_count: 0,
                last_success_at: None,
            });

        if success {
            entry.successful_count += 1;
            entry.last_success_at = Some(chrono::Utc::now().timestamp());
        } else {
            entry.failed_count += 1;
        }

        Ok(entry.clone())
    }
}

/// JetStream KV implementation of ReputationStore.
pub struct JetStreamReputationStore {
    js: async_nats::jetstream::Context,
}

impl JetStreamReputationStore {
    pub fn new(js: async_nats::jetstream::Context) -> Self {
        Self { js }
    }

    async fn get_store(&self) -> Result<async_nats::jetstream::kv::Store> {
        self.js
            .get_key_value("agent_reputation")
            .await
            .map_err(|e| anyhow::anyhow!("Reputation KV lookup failed: {e}"))
    }
}

#[async_trait]
impl ReputationStore for JetStreamReputationStore {
    async fn get_reputation(
        &self,
        tenant_id: &str,
        counterparty_did: &str,
    ) -> Result<CounterpartyReputation> {
        let key = format_reputation_key(tenant_id, counterparty_did);
        let store = match self.get_store().await {
            Ok(s) => s,
            Err(_) => {
                return Ok(CounterpartyReputation {
                    did: counterparty_did.to_string(),
                    successful_count: 0,
                    failed_count: 0,
                    last_success_at: None,
                })
            }
        };

        if let Ok(Some(entry)) = store.entry(&key).await {
            if let Ok(rep) = serde_json::from_slice::<CounterpartyReputation>(&entry.value) {
                return Ok(rep);
            }
        }

        Ok(CounterpartyReputation {
            did: counterparty_did.to_string(),
            successful_count: 0,
            failed_count: 0,
            last_success_at: None,
        })
    }

    async fn record_execution(
        &self,
        tenant_id: &str,
        counterparty_did: &str,
        success: bool,
    ) -> Result<CounterpartyReputation> {
        let key = format_reputation_key(tenant_id, counterparty_did);
        let store = self.get_store().await?;

        let mut rep = self.get_reputation(tenant_id, counterparty_did).await?;
        if success {
            rep.successful_count += 1;
            rep.last_success_at = Some(chrono::Utc::now().timestamp());
        } else {
            rep.failed_count += 1;
        }

        let bytes = serde_json::to_vec(&rep)?;
        store
            .put(&key, bytes.into())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to put reputation record: {e}"))?;

        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_reputation_key_uses_underscore() {
        let key = format_reputation_key("tenant_42", "did:web:company-a.com");
        assert!(!key.contains(':'));
        assert_eq!(key, "reputation_tenant_42_did_web_company-a_com");
    }

    #[tokio::test]
    async fn test_in_memory_reputation_store_increments() {
        let store = InMemoryReputationStore::new();
        let rep0 = store
            .get_reputation("tenant_1", "did:web:supplier.com")
            .await
            .unwrap();
        assert_eq!(rep0.successful_count, 0);

        let rep1 = store
            .record_execution("tenant_1", "did:web:supplier.com", true)
            .await
            .unwrap();
        assert_eq!(rep1.successful_count, 1);
        assert_eq!(rep1.failed_count, 0);
        assert!(rep1.last_success_at.is_some());

        let rep2 = store
            .record_execution("tenant_1", "did:web:supplier.com", false)
            .await
            .unwrap();
        assert_eq!(rep2.successful_count, 1);
        assert_eq!(rep2.failed_count, 1);
    }
}
