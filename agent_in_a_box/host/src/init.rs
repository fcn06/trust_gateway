use anyhow::{Result, Context};
// use std::sync::{Arc, Mutex};
use async_nats::jetstream::{self, kv::Store};
use webauthn_rs::prelude::*;
use url::Url;
use std::collections::HashMap;

use crate::shared_state::{HostConfig, ServerKeys};

// Load Configuration
pub fn load_config() -> Result<HostConfig> {
    let cwd = std::env::current_dir().unwrap_or_default();
    tracing::info!("📂 Loading configuration from CWD: {:?}", cwd);

    // Load .env files if present (e.g., host.env)
    dotenvy::dotenv().ok();
    if let Ok(path) = std::env::var("ENV_FILE") {
        dotenvy::from_filename(path).ok();
    }

    let loader = config::Config::builder()
        .add_source(config::File::with_name("config.json").required(false))
        .add_source(config::File::with_name("config/config.json").required(false))
        .add_source(config::File::with_name("../config.json").required(false))
        .add_source(config::Environment::with_prefix("APP").separator("__"))
        .add_source(config::Environment::default().separator("__")) // Allow flat environment variables
        .build()?;

    let config: HostConfig = loader.try_deserialize()?;
    tracing::info!("✅ Configuration loaded. API Listen: {}, Gateway Base: {}, Gateway DID: {}, Allowed Tenants: {}", 
        config.api_listen_url, config.service_gateway_base_url, config.gateway_did, config.allowed_agent_tenants);
    Ok(config)
}

// Setup NATS and KV Stores
pub async fn setup_nats(config: &HostConfig) -> Result<(async_nats::Client, HashMap<String, Store>)> {
    let nc = async_nats::connect(&config.nats_global_domain_url).await
        .context("Failed to connect to NATS")?;
    
    let js = jetstream::new(nc.clone());
    let mut kv_stores = HashMap::new();

    let buckets = vec![
        "vault", "acl", "username_to_userid", "user_credentials", 
        "user_profiles", "provisioning", "sovereign_kv", "dht_discovery", 
        "did_ledger", "published_dids", "contact_requests", "user_identity_metadata",
        "userid_to_aid", "escalation_requests", "contact_store",
        "pending_oid4vp_requests", "tenant_connections",
        "tenant_registry", "user_tenant_membership", "tenant_invites",
        "telegram_to_uid"
    ];

    // Multi-tenant: prefix bucket names when tenant_id is configured
    let tenant_prefix = if config.tenant_id.is_empty() {
        String::new()
    } else {
        format!("tenant_{}_", config.tenant_id)
    };

    for bucket in buckets {
        let actual_bucket = format!("{}{}", tenant_prefix, bucket);
        let store = match js.get_key_value(&actual_bucket).await {
            Ok(s) => s,
            Err(_) => {
                js.create_key_value(jetstream::kv::Config {
                    bucket: actual_bucket.clone(),
                    history: 1,
                    storage: jetstream::stream::StorageType::File,
                    ..Default::default()
                }).await.context(format!("Failed to create KV: {}", actual_bucket))?
            }
        };
        // Store with unprefixed key so existing code works unchanged
        kv_stores.insert(bucket.to_string(), store);
    }

    if !tenant_prefix.is_empty() {
        tracing::info!("🏢 Multi-tenant mode: KV buckets prefixed with '{}'", tenant_prefix);
    }

    // Provision an explicit Stream for audit events so they are persisted
    let stream_name = format!("{}agent_audit_stream", tenant_prefix);
    let audit_tenant_subject = if config.tenant_id.is_empty() {
        "audit.tenant.>".to_string()
    } else {
        format!("audit.tenant.{}.>", config.tenant_id)
    };
    let audit_action_subject = "audit.action.>".to_string();
    
    let stream_config = jetstream::stream::Config {
        name: stream_name.clone(),
        subjects: vec![audit_tenant_subject.clone(), audit_action_subject.clone()],
        max_messages: 1000,
        retention: jetstream::stream::RetentionPolicy::Limits,
        ..Default::default()
    };
    match js.get_or_create_stream(stream_config.clone()).await {
        Ok(_) => {
            if let Err(e) = js.update_stream(stream_config).await {
                tracing::warn!("Failed to update existing stream subjects: {}", e);
            }
            tracing::info!("✅ Audit Stream '{}' provisioned on '{}' and '{}'", stream_name, audit_tenant_subject, audit_action_subject);
        }
        Err(e) => tracing::error!("❌ Failed to create audit stream: {}", e),
    }

    Ok((nc, kv_stores))
}

// Setup WebAuthn
pub fn setup_webauthn(config: &HostConfig) -> Result<Webauthn> {
    let rp_origin = Url::parse(&config.webauthn_rp_origin)?;
    let mut builder = WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)?;
    // Allow additional origins (e.g., customer portal on a different port)
    for extra in &config.webauthn_rp_extra_origins {
        if let Ok(url) = Url::parse(extra) {
            builder = builder.append_allowed_origin(&url);
            tracing::info!("🔐 WebAuthn: Added extra allowed origin: {}", extra);
        }
    }
    let webauthn = builder.build()?;
    Ok(webauthn)
}

// Load or Generate Server Keys
pub fn load_server_keys() -> Result<ServerKeys> {
    let path = std::path::Path::new("config/server.keys");
    let mut keys = if path.exists() {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str::<ServerKeys>(&content)?
    } else {
        tracing::warn!("⚠️ server.keys not found, generating new keys...");
        let mut rng = rand::thread_rng();
        let mut house_salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut house_salt);
        
        let mut jwt_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut jwt_seed);
        
        let k = ServerKeys {
            house_salt: house_salt.to_vec(),
            jwt_key_bytes: jwt_seed.to_vec(),
        };
        
        // Ensure config dir exists
        std::fs::create_dir_all("config")?;
        std::fs::write(path, serde_json::to_string_pretty(&k)?)?;
        k
    };

    // Override JWT key if environment variable is set (synchronization for dev mode)
    if let Ok(env_secret) = std::env::var("JWT_SECRET") {
        if !env_secret.is_empty() {
            tracing::info!("🔐 Syncing JWT key with environment (JWT_SECRET set, len={})", env_secret.len());
            keys.jwt_key_bytes = env_secret.as_bytes().to_vec();
        }
    }

    Ok(keys)
}

/// One-time migration: backfill `thid_{thid} -> msg_id` index entries in `sovereign_kv`.
///
/// Messages written before the thid index was introduced lack the secondary
/// index key. This function scans all non-index entries and creates the
/// missing index entries, enabling O(1) lookups in `check_handshake_status_handler`.
///
/// Safe to run on every startup — it skips entries that already have an index.
pub async fn backfill_thid_index(kv: &async_nats::jetstream::kv::Store) {
    use futures::StreamExt;

    let mut keys_stream = match kv.keys().await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("⚠️ [thid backfill] Could not list sovereign_kv keys: {}", e);
            return;
        }
    };

    let mut all_keys = Vec::new();
    while let Some(Ok(key)) = keys_stream.next().await {
        if !key.starts_with("thid_") {
            all_keys.push(key);
        }
    }

    let mut count = 0u32;
    for key in &all_keys {
        if let Ok(Some(entry)) = kv.get(key).await {
            if let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&entry) {
                if let Some(thid) = msg["thid"].as_str() {
                    let idx_key = format!("thid_{}", thid);
                    // Only write if the index key doesn't already exist
                    if let Ok(None) = kv.get(&idx_key).await {
                        let _ = kv.put(idx_key, key.as_bytes().to_vec().into()).await;
                        count += 1;
                    }
                }
            }
        }
    }

    if count > 0 {
        tracing::info!("📇 [thid backfill] Created {} missing thid index entries", count);
    } else {
        tracing::debug!("📇 [thid backfill] No missing index entries — all up to date");
    }
}
