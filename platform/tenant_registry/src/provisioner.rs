//! Tenant provisioner — creates NATS KV namespaces for new tenants.
//!
//! When a tenant is created, this module provisions:
//! - `tenant_<id>_sovereign_kv` — main message & state store
//! - `tenant_<id>_agent_audit` — audit event stream
//! - `tenant_<id>_escalation_requests` — human-in-the-loop approvals
//! - `tenant_<id>_contact_requests` — DIDComm contact request store
//! - `tenant_<id>_user_identity_metadata` — user metadata / alias store
//! - `tenant_<id>_published_dids` — published DID registry
//! - `tenant_<id>_username_to_userid` — username lookup
//! - `tenant_<id>_user_profiles` — user profile data

use async_nats::jetstream;
use async_nats::jetstream::kv::Config as KvConfig;

/// The list of KV buckets provisioned per tenant.
const TENANT_KV_BUCKETS: &[&str] = &[
    "sovereign_kv",
    "agent_audit",
    "escalation_requests",
    "contact_requests",
    "user_identity_metadata",
    "published_dids",
    "username_to_userid",
    "user_profiles",
    "dht_discovery",
];

/// Provision all NATS KV buckets for a new tenant.
///
/// Each bucket is prefixed with `tenant_<tenant_id>_`.
/// This is idempotent — if a bucket already exists, it will be reused.
pub async fn provision_tenant_namespaces(
    js: &jetstream::Context,
    tenant_id: &str,
) -> anyhow::Result<Vec<String>> {
    let mut created = Vec::new();

    for bucket_suffix in TENANT_KV_BUCKETS {
        let bucket_name = format!("tenant_{}_{}", tenant_id, bucket_suffix);
        
        let config = KvConfig {
            bucket: bucket_name.clone(),
            description: format!(
                "Tenant {} — {} store",
                tenant_id, bucket_suffix
            ),
            history: match *bucket_suffix {
                "agent_audit" => 100,  // Keep more history for audit
                _ => 5,
            },
            ..Default::default()
        };

        match js.create_key_value(config).await {
            Ok(_) => {
                tracing::info!("✅ Provisioned KV bucket: {}", bucket_name);
                created.push(bucket_name);
            }
            Err(e) => {
                tracing::error!("❌ Failed to provision KV bucket {}: {}", bucket_name, e);
                return Err(anyhow::anyhow!(
                    "Failed to provision bucket {}: {}",
                    bucket_name,
                    e
                ));
            }
        }
    }

    Ok(created)
}

/// Deprovision (delete) all NATS KV buckets for a tenant.
///
/// Used only for hard-delete or cleanup. Soft-delete keeps data.
pub async fn deprovision_tenant_namespaces(
    js: &jetstream::Context,
    tenant_id: &str,
) -> anyhow::Result<()> {
    for bucket_suffix in TENANT_KV_BUCKETS {
        let bucket_name = format!("tenant_{}_{}", tenant_id, bucket_suffix);
        match js.delete_key_value(&bucket_name).await {
            Ok(_) => tracing::info!("🗑️ Deleted KV bucket: {}", bucket_name),
            Err(e) => tracing::warn!("⚠️ Could not delete {}: {}", bucket_name, e),
        }
    }
    Ok(())
}
