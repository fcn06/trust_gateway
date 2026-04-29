// ─────────────────────────────────────────────────────────────
// Agent Registry — JetStream KV-backed implementation
//
// Uses NATS KV bucket "agent_registry" for durable storage.
// Follows the same pattern as JetStreamApprovalStore.
//
// Secondary index: KV bucket "agent_source_index" maps
// source_type values → agent_id for fast resolve_by_source.
// ─────────────────────────────────────────────────────────────

use trust_core::agent::*;
use trust_core::errors::StoreError;

pub struct JetStreamAgentRegistry {
    js: async_nats::jetstream::Context,
}

impl JetStreamAgentRegistry {
    pub fn new(js: async_nats::jetstream::Context) -> Self {
        Self { js }
    }

    async fn get_store(&self) -> Result<async_nats::jetstream::kv::Store, StoreError> {
        self.js
            .get_key_value("agent_registry")
            .await
            .map_err(|e| StoreError::Backend(format!("KV access failed: {}", e)))
    }

    async fn get_index_store(&self) -> Result<async_nats::jetstream::kv::Store, StoreError> {
        self.js
            .get_key_value("agent_source_index")
            .await
            .map_err(|e| StoreError::Backend(format!("KV index access failed: {}", e)))
    }

    /// Write the source_type → agent_id mapping to the secondary index.
    async fn index_source(&self, agent_id: &str, agent_type: AgentType, policy_profile: &str) {
        // Build a lookup key from the agent_type to enable resolve_by_source.
        let source_key = format!("type_{}", agent_type);
        let agent_id_owned = agent_id.to_string();
        let agent_id_vec = agent_id_owned.as_bytes().to_vec();

        if let Ok(index) = self.get_index_store().await {
            // Index by policy_profile (commonly maps to source-level identity)
            let _ = index.put(
                &format!("profile_{}", policy_profile),
                agent_id_vec.clone().into(),
            ).await;

            // Index by type
            let _ = index.put(
                &source_key,
                agent_id_vec.clone().into(),
            ).await;

            // Also index by agent_id itself for direct lookup
            let _ = index.put(
                &format!("id_{}", agent_id),
                agent_id_vec.into(),
            ).await;
        }
    }
}

#[async_trait::async_trait]
impl trust_core::traits::AgentRegistry for JetStreamAgentRegistry {
    async fn register(&self, req: RegisterAgentRequest) -> Result<AgentRecord, StoreError> {
        let store = self.get_store().await?;
        let agent_id = uuid::Uuid::new_v4().to_string();

        let record = AgentRecord {
            agent_id: agent_id.clone(),
            name: req.name,
            owner: req.owner,
            agent_type: req.agent_type,
            environment: req.environment,
            policy_profile: req.policy_profile.clone(),
            allowed_tools: req.allowed_tools,
            delegated_identity: req.delegated_identity,
            status: AgentStatus::Active,
            kill_switch: false,
            created_at: chrono::Utc::now(),
            last_seen: None,
            metadata: req.metadata,
        };

        let json = serde_json::to_vec(&record)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        store
            .put(&agent_id, json.into())
            .await
            .map_err(|e| StoreError::Backend(format!("KV put failed: {}", e)))?;

        // Update secondary index
        self.index_source(&agent_id, record.agent_type, &record.policy_profile).await;

        tracing::info!("📋 Registered agent: {} ({}) [{}]", record.name, agent_id, record.agent_type);
        Ok(record)
    }

    async fn get(&self, agent_id: &str) -> Result<Option<AgentRecord>, StoreError> {
        let store = self.get_store().await?;
        match store.get(agent_id).await {
            Ok(Some(entry)) => {
                let record: AgentRecord = serde_json::from_slice(&entry)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Backend(format!("KV get failed: {}", e))),
        }
    }

    async fn update(&self, agent_id: &str, req: UpdateAgentRequest) -> Result<AgentRecord, StoreError> {
        let store = self.get_store().await?;

        let mut record = match self.get(agent_id).await? {
            Some(r) => r,
            None => return Err(StoreError::NotFound { id: agent_id.to_string() }),
        };

        // Apply partial updates
        if let Some(name) = req.name { record.name = name; }
        if let Some(owner) = req.owner { record.owner = owner; }
        if let Some(environment) = req.environment { record.environment = environment; }
        if let Some(policy_profile) = req.policy_profile {
            record.policy_profile = policy_profile;
        }
        if let Some(allowed_tools) = req.allowed_tools { record.allowed_tools = allowed_tools; }
        if let Some(delegated_identity) = req.delegated_identity {
            record.delegated_identity = delegated_identity;
        }
        if let Some(status) = req.status { record.status = status; }
        if let Some(kill_switch) = req.kill_switch { record.kill_switch = kill_switch; }
        if let Some(metadata) = req.metadata { record.metadata = metadata; }

        let json = serde_json::to_vec(&record)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        store
            .put(agent_id, json.into())
            .await
            .map_err(|e| StoreError::Backend(format!("KV put failed: {}", e)))?;

        // Re-index
        self.index_source(agent_id, record.agent_type, &record.policy_profile).await;

        tracing::info!("📋 Updated agent: {} ({})", record.name, agent_id);
        Ok(record)
    }

    async fn list(&self, status_filter: Option<AgentStatus>) -> Result<Vec<AgentRecord>, StoreError> {
        let store = self.get_store().await?;
        let mut records = Vec::new();

        use futures::StreamExt;
        let mut keys = store.keys().await.map_err(|e| StoreError::Backend(e.to_string()))?;

        let mut keys_vec = Vec::new();
        while let Some(key_res) = keys.next().await {
            if let Ok(key) = key_res {
                keys_vec.push(key);
            }
        }

        for key in keys_vec {
            if let Ok(Some(entry)) = store.get(&key).await {
                if let Ok(record) = serde_json::from_slice::<AgentRecord>(&entry) {
                    if let Some(filter) = &status_filter {
                        if record.status != *filter {
                            continue;
                        }
                    }
                    records.push(record);
                }
            }
        }

        // Sort by created_at descending (newest first)
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(records)
    }

    async fn kill(&self, agent_id: &str) -> Result<(), StoreError> {
        let store = self.get_store().await?;

        let mut record = match self.get(agent_id).await? {
            Some(r) => r,
            None => return Err(StoreError::NotFound { id: agent_id.to_string() }),
        };

        record.kill_switch = true;

        let json = serde_json::to_vec(&record)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        store
            .put(agent_id, json.into())
            .await
            .map_err(|e| StoreError::Backend(format!("KV put failed: {}", e)))?;

        tracing::warn!("🔴 KILL SWITCH activated for agent: {} ({})", record.name, agent_id);
        Ok(())
    }

    async fn revive(&self, agent_id: &str) -> Result<(), StoreError> {
        let store = self.get_store().await?;

        let mut record = match self.get(agent_id).await? {
            Some(r) => r,
            None => return Err(StoreError::NotFound { id: agent_id.to_string() }),
        };

        record.kill_switch = false;

        let json = serde_json::to_vec(&record)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        store
            .put(agent_id, json.into())
            .await
            .map_err(|e| StoreError::Backend(format!("KV put failed: {}", e)))?;

        tracing::info!("🟢 Kill switch deactivated for agent: {} ({})", record.name, agent_id);
        Ok(())
    }

    async fn touch(&self, agent_id: &str) -> Result<(), StoreError> {
        let store = self.get_store().await?;

        let mut record = match self.get(agent_id).await? {
            Some(r) => r,
            None => return Ok(()), // Silently skip if agent not found (fire-and-forget)
        };

        record.last_seen = Some(chrono::Utc::now());

        let json = serde_json::to_vec(&record)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        store
            .put(agent_id, json.into())
            .await
            .map_err(|e| StoreError::Backend(format!("KV put failed: {}", e)))?;

        Ok(())
    }

    async fn resolve_by_source(&self, source_type: &str) -> Result<Option<AgentRecord>, StoreError> {
        // Strategy: try to find an agent whose policy_profile matches the source_type,
        // or whose agent_id matches the source_type directly.
        //
        // 1. Try direct lookup by agent_id
        if let Some(record) = self.get(source_type).await? {
            return Ok(Some(record));
        }

        // 2. Try the secondary index: profile:<source_type>
        if let Ok(index) = self.get_index_store().await {
            let lookup_key = format!("profile_{}", source_type);
            if let Ok(Some(entry)) = index.get(&lookup_key).await {
                let agent_id = String::from_utf8_lossy(&entry).to_string();
                return self.get(&agent_id).await;
            }
        }

        // 3. Fallback: scan all agents for matching source_type patterns
        // This covers cases like ssi_agent → internal_agent, picoclaw → picoclaw_default
        let all = self.list(None).await?;
        for agent in &all {
            // Match by policy_profile prefix or by agent_id
            if agent.policy_profile.starts_with(source_type)
                || agent.agent_id == source_type
                || (source_type == "ssi_agent" && agent.policy_profile == "internal_default")
                || (source_type == "picoclaw" && agent.policy_profile == "picoclaw_default")
            {
                return Ok(Some(agent.clone()));
            }
        }

        Ok(None)
    }
}



/// Bootstrap agents using direct JetStream access (preserves predefined agent_ids).
pub async fn bootstrap_from_toml_direct(
    js: &async_nats::jetstream::Context,
    path: &str,
) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("⚠️ No agent bootstrap config at '{}': {} (agents can be added via API)", path, e);
            return;
        }
    };

    let config: AgentBootstrapConfig = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("❌ Failed to parse agents.toml: {}", e);
            return;
        }
    };

    let store = match js.get_key_value("agent_registry").await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("❌ Cannot access agent_registry KV for bootstrap: {}", e);
            return;
        }
    };

    let index_store = js.get_key_value("agent_source_index").await.ok();

    for entry in config.agents {
        // Check if agent already exists
        match store.get(&entry.agent_id).await {
            Ok(Some(_)) => {
                tracing::debug!(
                    "📋 Bootstrap agent '{}' already registered — skipping",
                    entry.name
                );
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("⚠️ Could not check agent '{}': {}", entry.agent_id, e);
                continue;
            }
        }

        let record = AgentRecord {
            agent_id: entry.agent_id.clone(),
            name: entry.name.clone(),
            owner: entry.owner,
            agent_type: entry.agent_type,
            environment: entry.environment,
            policy_profile: entry.policy_profile.clone(),
            allowed_tools: entry.allowed_tools,
            delegated_identity: entry.delegated_identity,
            status: AgentStatus::Active,
            kill_switch: false,
            created_at: chrono::Utc::now(),
            last_seen: None,
            metadata: serde_json::Value::Null,
        };

        let json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("❌ Failed to serialize bootstrap agent '{}': {}", entry.agent_id, e);
                continue;
            }
        };

        match store.put(&entry.agent_id, json.into()).await {
            Ok(_) => {
                tracing::info!(
                    "📋 Bootstrapped agent: {} ({}) [{}]",
                    record.name, record.agent_id, record.agent_type
                );

                // Index by policy_profile
                if let Some(ref idx) = index_store {
                    let aid_vec = record.agent_id.as_bytes().to_vec();
                    let _ = idx.put(
                        &format!("profile_{}", record.policy_profile),
                        aid_vec.clone().into(),
                    ).await;
                    let _ = idx.put(
                        &format!("id_{}", record.agent_id),
                        aid_vec.into(),
                    ).await;
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to bootstrap agent '{}': {}", entry.agent_id, e);
            }
        }
    }
}
