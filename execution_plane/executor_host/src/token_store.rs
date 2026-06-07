use async_nats::jetstream;
use async_nats::jetstream::kv::Store;
use serde::{Deserialize, Serialize};

/// OAuth token record for a tenant + provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub tenant_id: String,
    pub provider: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    pub created_at: i64,
}

/// NATS KV-backed token store.
#[derive(Clone)]
pub struct TokenStore {
    kv: Store,
}

impl TokenStore {
    pub async fn new(js: jetstream::Context) -> anyhow::Result<Self> {
        let kv = match js.create_key_value(jetstream::kv::Config {
            bucket: "oauth_tokens".to_string(),
            description: "Tenant OAuth tokens".to_string(),
            history: 3,
            ..Default::default()
        }).await {
            Ok(store) => store,
            Err(e) => {
                tracing::warn!("⚠️ oauth_tokens KV bucket creation failed, trying to bind to existing: {}", e);
                js.get_key_value("oauth_tokens").await?
            }
        };
        Ok(Self { kv })
    }

    /// Store an OAuth token for a tenant + provider.
    pub async fn store_token(&self, token: &OAuthToken) -> anyhow::Result<()> {
        // RULE 020: Use _ as separator for composite Jetstream keys
        let key = format!("{}_{}", token.tenant_id.replace('.', "_"), token.provider);
        let data = serde_json::to_vec(token)?;
        self.kv.put(&key, data.into()).await?;
        tracing::info!(
            "🔑 Stored OAuth token for tenant {} provider {}",
            token.tenant_id,
            token.provider
        );
        Ok(())
    }

    /// Retrieve an OAuth token for a tenant + provider.
    pub async fn get_token(
        &self,
        tenant_id: &str,
        provider: &str,
    ) -> anyhow::Result<Option<OAuthToken>> {
        // RULE 020: Use _ as separator for composite Jetstream keys
        let key = format!("{}_{}", tenant_id.replace('.', "_"), provider);
        match self.kv.get(&key).await {
            Ok(Some(entry)) => {
                let token: OAuthToken = serde_json::from_slice(&entry)?;
                Ok(Some(token))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Token store error: {}", e)),
        }
    }

    /// Check if a token is still valid (not expired).
    pub fn is_token_valid(token: &OAuthToken) -> bool {
        let now = chrono::Utc::now().timestamp();
        // Add 30s buffer
        token.expires_at > (now + 30)
    }
}
