//! NATS KV-backed tenant storage.
//!
//! Stores `Tenant` records in a NATS JetStream KV bucket called `tenant_registry`.
//! Provides CRUD operations and tenant listing.

use async_nats::jetstream;
use async_nats::jetstream::kv::Store as KvStore;
use tenant_context::{Tenant, TenantStatus};
use futures::StreamExt;

/// Persistent store for tenant records, backed by NATS JetStream KV.
#[derive(Clone)]
pub struct TenantStore {
    kv: KvStore,
}

impl TenantStore {
    /// Create (or bind to) the `tenant_registry` KV bucket.
    pub async fn new(js: jetstream::Context) -> anyhow::Result<Self> {
        let kv = js.create_key_value(jetstream::kv::Config {
            bucket: "tenant_registry".to_string(),
            description: "Tenant Registry — control plane storage".to_string(),
            history: 5,
            ..Default::default()
        }).await?;
        Ok(Self { kv })
    }

    /// Insert a new tenant record.
    pub async fn put(&self, tenant: &Tenant) -> anyhow::Result<()> {
        let key = tenant.tenant_id.to_string();
        let value = serde_json::to_vec(tenant)?;
        self.kv.put(&key, value.into()).await?;
        tracing::info!("💾 Stored tenant: {} ({})", tenant.display_name, key);
        Ok(())
    }

    /// Get a tenant by ID.
    pub async fn get(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>> {
        match self.kv.get(tenant_id).await {
            Ok(Some(entry)) => {
                let tenant: Tenant = serde_json::from_slice(&entry)?;
                Ok(Some(tenant))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("KV get error: {}", e)),
        }
    }

    /// List all tenants (excluding soft-deleted by default).
    pub async fn list(&self, include_deleted: bool) -> anyhow::Result<Vec<Tenant>> {
        let mut tenants = Vec::new();
        let mut keys = self.kv.keys().await?;
        while let Some(Ok(key)) = keys.next().await {
            if let Ok(Some(entry)) = self.kv.get(&key).await {
                if let Ok(tenant) = serde_json::from_slice::<Tenant>(&entry) {
                    if include_deleted || tenant.status != TenantStatus::Deleted {
                        tenants.push(tenant);
                    }
                }
            }
        }
        Ok(tenants)
    }

    /// Soft-delete a tenant (set status to Deleted).
    pub async fn soft_delete(&self, tenant_id: &str) -> anyhow::Result<bool> {
        if let Some(mut tenant) = self.get(tenant_id).await? {
            tenant.status = TenantStatus::Deleted;
            self.put(&tenant).await?;
            tracing::info!("🗑️ Soft-deleted tenant: {}", tenant_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
