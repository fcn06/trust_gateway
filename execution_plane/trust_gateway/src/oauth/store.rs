use anyhow::Result;
use async_nats::jetstream::kv::Store;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeEntry {
    pub code: String,
    pub client_id: String,
    pub did: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: String,
    pub created_at: i64,
    pub expires_at: i64,
}

pub struct AuthCodeStore {
    kv: Store,
}

impl AuthCodeStore {
    pub fn new(kv: Store) -> Self {
        Self { kv }
    }

    pub async fn store(&self, entry: &AuthCodeEntry) -> Result<()> {
        let payload = serde_json::to_vec(entry)?;
        self.kv.put(&entry.code, payload.into()).await?;
        Ok(())
    }

    pub async fn get(&self, code: &str) -> Result<Option<AuthCodeEntry>> {
        if let Some(entry) = self.kv.entry(code).await? {
            let record: AuthCodeEntry = serde_json::from_slice(&entry.value)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub async fn delete(&self, code: &str) -> Result<()> {
        self.kv.delete(code).await?;
        Ok(())
    }
}
