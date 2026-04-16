//! Axum HTTP handlers for the Tenant Registry API.

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::models::*;
use crate::provisioner;
use crate::AppState;
use tenant_context::{Tenant, TenantStatus};

/// POST /tenants — Create a new tenant and provision its NATS namespaces.
pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<CreateTenantResponse>), (StatusCode, String)> {
    let tenant_id = Uuid::new_v4();
    let tier = req.tier.unwrap_or_default();
    let key_mode = req.key_mode.unwrap_or_default();
    let llm_policy = LlmPolicy::default_for_tier(&tier);
    let vault_namespace = format!("tenant_{}", tenant_id);
    let nats_account_id = format!("nats_account_{}", tenant_id);

    let tenant = Tenant {
        tenant_id,
        display_name: req.display_name.clone(),
        tier: tier.clone(),
        status: TenantStatus::Active,
        created_at: chrono::Utc::now().timestamp(),
        nats_account_id: nats_account_id.clone(),
        vault_namespace: vault_namespace.clone(),
        llm_policy_id: llm_policy.policy_id.clone(),
        key_mode,
        service_did: Some(format!("did:twin:tenant:{}", tenant_id)),
    };

    // 1. Provision NATS KV namespaces
    provisioner::provision_tenant_namespaces(&state.js, &tenant_id.to_string())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Provisioning failed: {}", e),
            )
        })?;

    // 2. Store the LLM policy
    let policy_bytes = serde_json::to_vec(&llm_policy).unwrap();
    if let Err(e) = state
        .llm_policy_store
        .put(&llm_policy.policy_id, policy_bytes.into())
        .await
    {
        tracing::warn!("⚠️ Failed to store LLM policy: {}", e);
    }

    // 3. Persist tenant record
    state.store.put(&tenant).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Store error: {}", e),
        )
    })?;

    tracing::info!(
        "🏢 Created tenant: {} ({}) — tier: {}",
        req.display_name,
        tenant_id,
        tier
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateTenantResponse {
            tenant_id: tenant_id.to_string(),
            display_name: req.display_name,
            tier,
            status: TenantStatus::Active,
            nats_account_id,
            vault_namespace,
        }),
    ))
}

/// GET /tenants/:id — Read a tenant by ID.
pub async fn get_tenant(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Tenant>, StatusCode> {
    match state.store.get(&tenant_id).await {
        Ok(Some(tenant)) => Ok(Json(tenant)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// GET /tenants — List all tenants.
pub async fn list_tenants(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<TenantSummary>>, StatusCode> {
    let tenants = state
        .store
        .list(false)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let summaries: Vec<TenantSummary> = tenants
        .into_iter()
        .map(|t| TenantSummary {
            tenant_id: t.tenant_id.to_string(),
            display_name: t.display_name,
            tier: t.tier,
            status: t.status,
        })
        .collect();

    Ok(Json(summaries))
}

/// PATCH /tenants/:id/tier — Update a tenant's tier.
pub async fn update_tier(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    Json(req): Json<UpdateTierRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut tenant = state
        .store
        .get(&tenant_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let old_tier = tenant.tier.clone();
    tenant.tier = req.tier.clone();

    // Generate new LLM policy for the new tier
    let new_policy = LlmPolicy::default_for_tier(&req.tier);
    tenant.llm_policy_id = new_policy.policy_id.clone();

    // Store updated policy
    let policy_bytes = serde_json::to_vec(&new_policy).unwrap();
    if let Err(e) = state
        .llm_policy_store
        .put(&new_policy.policy_id, policy_bytes.into())
        .await
    {
        tracing::warn!("⚠️ Failed to store updated LLM policy: {}", e);
    }

    state
        .store
        .put(&tenant)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        "📈 Updated tenant {} tier: {} → {}",
        tenant_id,
        old_tier,
        req.tier
    );

    Ok(Json(serde_json::json!({
        "status": "updated",
        "tenant_id": tenant_id,
        "old_tier": old_tier.to_string(),
        "new_tier": req.tier.to_string(),
        "new_policy_id": new_policy.policy_id
    })))
}

/// DELETE /tenants/:id — Soft-delete a tenant.
pub async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let deleted = state
        .store
        .soft_delete(&tenant_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if deleted {
        Ok(Json(
            serde_json::json!({"status": "deleted", "tenant_id": tenant_id}),
        ))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// GET /tenants/:id/policy — Get the LLM policy for a tenant.
pub async fn get_tenant_policy(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<LlmPolicy>, StatusCode> {
    let tenant = state
        .store
        .get(&tenant_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    match state.llm_policy_store.get(&tenant.llm_policy_id).await {
        Ok(Some(entry)) => {
            let policy: LlmPolicy =
                serde_json::from_slice(&entry).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(policy))
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

// === Connection Model (V6): Wallet Connections ===

/// Generate a composite key for tenant connections: `tenant_id:pairwise_did`
fn connection_key(tenant_id: &str, pairwise_did: &str) -> String {
    format!("{}:{}", tenant_id, pairwise_did)
}

/// GET /tenants/:id/connections — List all wallet connections for a tenant.
pub async fn list_connections(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<ConnectionSummary>>, StatusCode> {
    // Basic validation that tenant exists
    if state.store.get(&tenant_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut summaries = Vec::new();
    // In a real system, we'd use NATS KV watch or subject filtering.
    // Here we iterate keys and filter by prefix because NATS KV doesn't natively support prefix scans well without a watcher.
    // For simplicity in this iteration, we grab all keys and filter.
    if let Ok(mut keys) = state.connections_kv.keys().await {
        use futures::StreamExt;
        let prefix = format!("{}:", tenant_id);
        
        while let Some(Ok(key)) = keys.next().await {
            if key.starts_with(&prefix) {
                if let Ok(Some(entry)) = state.connections_kv.get(&key).await {
                    if let Ok(record) = serde_json::from_slice::<ConnectionRecord>(&entry) {
                        summaries.push(ConnectionSummary {
                            pairwise_did: record.pairwise_did,
                            connected_at: record.connected_at,
                            status: record.status,
                        });
                    }
                }
            }
        }
    }

    Ok(Json(summaries))
}

/// POST /tenants/:id/connections — Register a new wallet connection.
pub async fn create_connection(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    Json(req): Json<CreateConnectionRequest>,
) -> Result<(StatusCode, Json<ConnectionSummary>), StatusCode> {
    // Ensure tenant exists
    if state.store.get(&tenant_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let key = connection_key(&tenant_id, &req.pairwise_did);
    let now = chrono::Utc::now().timestamp();

    let record = ConnectionRecord {
        pairwise_did: req.pairwise_did.clone(),
        service_did: format!("did:twin:tenant:{}", tenant_id), // Simplified service DID mapping
        ucan_token: req.ucan_token,
        connected_at: now,
        status: "active".to_string(),
    };

    let bytes = serde_json::to_vec(&record).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    state.connections_kv.put(&key, bytes.into()).await.map_err(|e| {
        tracing::error!("❌ Failed to store connection: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("🤝 Registered connection: {} -> {}", req.pairwise_did, tenant_id);

    Ok((
        StatusCode::CREATED,
        Json(ConnectionSummary {
            pairwise_did: record.pairwise_did,
            connected_at: record.connected_at,
            status: record.status,
        }),
    ))
}

/// DELETE /tenants/:id/connections/:did — Revoke a wallet connection.
pub async fn revoke_connection(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, pairwise_did)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let key = connection_key(&tenant_id, &pairwise_did);
    
    // Check if exists first (so we can return 404)
    if state.connections_kv.get(&key).await.ok().flatten().is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Delete from KV
    state.connections_kv.delete(&key).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    tracing::info!("❌ Revoked connection: {} -> {}", pairwise_did, tenant_id);

    Ok(Json(serde_json::json!({
        "status": "revoked",
        "tenant_id": tenant_id,
        "pairwise_did": pairwise_did
    })))
}
