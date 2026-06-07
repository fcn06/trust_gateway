use std::sync::Arc;
use wasmtime::{Engine, component::{Component, Linker}};
use tokio::sync::mpsc::Receiver;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use crate::shared_state::{HostState, WebauthnSharedState};
use crate::commands::VaultCommand;
use crate::bindings::vault_bindgen;
use super::create_store;

/// REC-4: VaultPool — pre-instantiates N Wasm stores to eliminate contention.
///
/// The single-store vault loop was a bottleneck under concurrent calls because
/// Wasmtime `Store` is `!Send` — only one call can execute at a time. The pool
/// spawns multiple independent workers, each owning their own `Store`, and
/// distributes commands round-robin.
///
/// Default pool size: 4 (configurable via `VAULT_POOL_SIZE` env var).
const DEFAULT_POOL_SIZE: usize = 4;

fn pool_size() -> usize {
    std::env::var("VAULT_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_POOL_SIZE)
        .max(1)
}

// 1. Vault Loop Task (REC-4: pool-based)
pub fn spawn_vault_loop(
    engine: Engine,
    shared: Arc<WebauthnSharedState>,
    vault_comp: Component,
    linker: Linker<HostState>,
    mut vault_rx: Receiver<VaultCommand>,
) {
    let n = pool_size();
    tracing::info!("🔐 VaultPool: spawning {} workers (was 1)", n);

    // Create N worker channels
    let mut worker_txs: Vec<tokio::sync::mpsc::Sender<VaultCommand>> = Vec::with_capacity(n);

    for worker_id in 0..n {
        let (worker_tx, worker_rx) = tokio::sync::mpsc::channel::<VaultCommand>(64);
        worker_txs.push(worker_tx);

        let engine = engine.clone();
        let shared = shared.clone();
        let vault_comp = vault_comp.clone();
        let linker = linker.clone();

        // Each worker owns its own Store — no shared mutable state
        spawn_vault_worker(worker_id, engine, shared, vault_comp, linker, worker_rx);
    }

    // Dispatcher: consistent hashing to workers based on user_id
    tokio::spawn(async move {
        let mut next_rr = 0usize;
        while let Some(cmd) = vault_rx.recv().await {
            let worker_index = if let Some(uid) = cmd.user_id() {
                // Consistent Hashing: same user always goes to the same worker
                let mut hasher = DefaultHasher::new();
                uid.hash(&mut hasher);
                (hasher.finish() as usize) % worker_txs.len()
            } else {
                // Round-robin for commands without a specific user_id context
                let idx = next_rr;
                next_rr = (next_rr + 1) % worker_txs.len();
                idx
            };

            if let Err(e) = worker_txs[worker_index].send(cmd).await {
                tracing::error!(
                    "❌ VaultPool: worker {} channel closed: {}",
                    worker_index,
                    e
                );
            }
        }
        tracing::warn!("⚠️ VaultPool dispatcher exiting (command channel closed)");
    });
}

/// Spawn a single vault worker with its own Wasm Store.
fn spawn_vault_worker(
    worker_id: usize,
    engine: Engine,
    shared: Arc<WebauthnSharedState>,
    vault_comp: Component,
    linker: Linker<HostState>,
    mut vault_rx: Receiver<VaultCommand>,
) {
    tokio::spawn(async move {
        let mut store = create_store(&engine, shared.clone());
        let inst = linker.instantiate_async(&mut store, &vault_comp).await.expect("Vault init failed");
        store.data_mut().vault = Some(inst);

        tracing::debug!("🔐 VaultPool worker {} ready", worker_id);

        
        while let Some(cmd) = vault_rx.recv().await {
            let inst_opt = store.data().vault.clone();
            match cmd {
                VaultCommand::ListIdentities(username, resp) => {
                        let mut resp_opt = Some(resp);
                        if let Some(inst) = inst_opt {
                        let mut resp_sent = false;
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_list_identities(&mut store, &username).await {
                                Ok(Ok(identities)) => {
                                    if let Some(r) = resp_opt.take() { let _ = r.send(identities); }
                                    resp_sent = true;
                                },
                                Ok(Err(e)) => {
                                    tracing::error!("❌ Vault ListIdentities FAILED: {}", e);
                                },
                                Err(e) => {
                                    tracing::error!("❌ Vault ListIdentities TRAPPED: {:?}", e);
                                }
                            }
                        }
                        if !resp_sent {
                            // tracing::error!("❌ Vault ListIdentities failed");
                            if let Some(r) = resp_opt.take() { let _ = r.send(vec![]); }
                        }
                        } else {
                            if let Some(r) = resp_opt.take() { let _ = r.send(vec![]); }
                        }
                },
                VaultCommand::SetActiveDid(username, did, resp) => {
                        let mut resp_opt = Some(resp);
                        if let Some(inst) = inst_opt {
                            if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                                let vault_iface = vault_client.sovereign_gateway_vault();
                                let res = vault_iface.call_set_active_did(&mut store, &username, &did).await;
                                if let Some(r) = resp_opt.take() { 
                                    match res {
                                        Ok(inner_res) => { let _ = r.send(inner_res.map_err(|e| e.to_string())); },
                                        Err(e) => { let _ = r.send(Err(e.to_string())); }
                                    }
                                }
                            } else {
                                if let Some(r) = resp_opt.take() { let _ = r.send(Err("Failed to wrap vault".to_string())); }
                            }
                        } else {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".to_string())); }
                        }
                },
                VaultCommand::GetActiveDid(username, resp) => {
                        let mut resp_opt = Some(resp);
                        if let Some(inst) = inst_opt {
                            if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                                let vault_iface = vault_client.sovereign_gateway_vault();
                                match vault_iface.call_get_active_did(&mut store, &username).await {
                                    Ok(Ok(did)) => {
                                        if let Some(r) = resp_opt.take() { let _ = r.send(did); }
                                    },
                                    Ok(Err(e)) => {
                                        tracing::warn!("⚠️ Vault GetActiveDid returned error: {}", e);
                                    },
                                    Err(e) => {
                                        tracing::error!("❌ Vault GetActiveDid TRAPPED: {:?}", e);
                                    }
                                }
                            }
                            if let Some(r) = resp_opt.take() { let _ = r.send(String::new()); }
                        } else {
                            if let Some(r) = resp_opt.take() { let _ = r.send(String::new()); }
                        }
                },
                VaultCommand::GetPublishedDids(user_id, resp) => {
                    let mut published_dids = Vec::new();
                    if let Some(kv_stores) = &shared.kv_stores {
                        if let Some(pub_store) = kv_stores.get("published_dids") {
                             if let Ok(Some(entry)) = pub_store.get(&user_id).await {
                                  if let Ok(dids) = serde_json::from_slice::<Vec<String>>(&entry) {
                                      published_dids = dids;
                                  }
                             }
                        }
                    }
                    let _ = resp.send(published_dids);
                },
                VaultCommand::CreateIdentity(user_id, resp) => {
                    tracing::info!("🛠️ Processing VaultCommand::CreateIdentity for user {}", user_id);
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_create_identity(&mut store, &user_id).await {
                                Ok(Ok(did)) => {
                                    tracing::info!("✅ Vault CreateIdentity SUCCESS: {}", did);
                                    let target_id = crate::logic::compute_local_subject(&did, &store.data().shared.house_salt);
                                    let mut map = store.data().shared.target_id_map.write().await;
                                    map.insert(target_id, did.clone());
                                    if let Some(r) = resp_opt.take() { let _ = r.send(did); }
                                },
                                Ok(Err(e)) => {
                                    tracing::error!("❌ Vault CreateIdentity FAILED for user {}: {}", user_id, e);
                                },
                                Err(e) => {
                                    tracing::error!("❌ Vault CreateIdentity TRAPPED for user {}: {:?}", user_id, e);
                                }
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(String::new()); }
                },
                VaultCommand::CreatePeerIdentity(user_id, resp) => {
                    tracing::info!("🛠️ Processing VaultCommand::CreatePeerIdentity for user {}", user_id);
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_create_peer_identity(&mut store, &user_id).await {
                                Ok(Ok(did)) => {
                                    tracing::info!("✅ Vault CreatePeerIdentity SUCCESS: {}", did);
                                    let target_id = crate::logic::compute_local_subject(&did, &store.data().shared.house_salt);
                                    let mut map = store.data().shared.target_id_map.write().await;
                                    map.insert(target_id, did.clone());
                                    if let Some(r) = resp_opt.take() { let _ = r.send(did); }
                                },
                                Ok(Err(e)) => {
                                    tracing::error!("❌ Vault CreatePeerIdentity FAILED for user {}: {}", user_id, e);
                                },
                                Err(e) => {
                                    tracing::error!("❌ Vault CreatePeerIdentity TRAPPED for user {}: {:?}", user_id, e);
                                }
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(String::new()); }
                },
                VaultCommand::ResolveDid { did, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_resolve_did_to_user_id(&mut store, &did).await {
                                Ok(Ok(user_id)) => {
                                    if !user_id.is_empty() {
                                        if let Some(r) = resp_opt.take() { let _ = r.send(Some(user_id)); }
                                    }
                                },
                                Ok(Err(e)) => {
                                    tracing::warn!("⚠️ Vault ResolveDid FAILED: {}", e);
                                },
                                Err(e) => {
                                    tracing::error!("❌ Vault ResolveDid TRAPPED: {:?}", e);
                                }
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(None); }
                },
                VaultCommand::SignMessage { user_id, did, msg, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_sign_message(&mut store, &did, &msg).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault error".to_string())); }
                },
                VaultCommand::GenerateMasterSeed { user_id, derivation_path, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_generate_master_seed(&mut store, &user_id, &derivation_path).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::DeriveLinkNkey { user_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_derive_link_nkey(&mut store, &user_id).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::UnlockVault { user_id, derivation_path, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_unlock_vault(&mut store, &user_id, &derivation_path).await {
                                Ok(Ok(res)) => { 
                                    if res {
                                        // Unlocked successfully! Let's fetch all identities for this user and populate target_id_map!
                                        if let Ok(Ok(identities)) = vault_iface.call_list_identities(&mut store, &user_id).await {
                                            let mut map = store.data().shared.target_id_map.write().await;
                                            let salt = store.data().shared.house_salt.clone();
                                            for did in identities {
                                                let target_id = crate::logic::compute_local_subject(&did, &salt);
                                                map.insert(target_id, did);
                                            }
                                        }
                                    }
                                    if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } 
                                },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::IsUnlocked { user_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            let res = vault_iface.call_is_unlocked(&mut store, &user_id).await.unwrap_or(false);
                            if let Some(r) = resp_opt.take() { let _ = r.send(res); }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(false); }
                },
                VaultCommand::GetHmacSecret { user_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_get_hmac_secret(&mut store, &user_id).await {
                                Ok(res) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::EncryptRoutingToken { routing_key, target_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_encrypt_routing_token(&mut store, &routing_key, &target_id).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault error".to_string())); }
                },
                // NEW: DID Document generation (Hybrid Architecture)
                VaultCommand::CreateDidDocument { user_id, gateway_url, target_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_create_did_document(&mut store, &user_id, &gateway_url, &target_id).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::EcdhHandshake { user_id, did, peer_pubkey, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_ecdh_handshake(&mut store, &did, &peer_pubkey).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::IssueSessionJwt { user_id, subject, scope, user_did, ttl_seconds, tenant_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            // Wasm component expects &[String] for scope
                            match vault_iface.call_issue_session_jwt(&mut store, &subject, &scope, &user_did, ttl_seconds, &tenant_id).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::CreateServiceDid { tenant_id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(vault_client) = vault_bindgen::SsiVault::new(&mut store, &inst) {
                            let vault_iface = vault_client.sovereign_gateway_vault();
                            match vault_iface.call_create_service_did(&mut store, &tenant_id).await {
                                Ok(Ok(res)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Ok(res)); } },
                                Ok(Err(e)) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                                Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("{:?}", e))); } },
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(Err("Vault not loaded".into())); }
                },
                VaultCommand::RegisterConnection { pairwise_did, ucan_token, resp } => {
                    // Store connection in NATS KV (connections_kv)
                    let result = if let Some(kv) = store.data().shared.kv_stores.as_ref()
                        .and_then(|m| m.get("connections_kv")) 
                    {
                        let connection = serde_json::json!({
                            "pairwise_did": pairwise_did,
                            "ucan_token": ucan_token,
                            "connected_at": std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            "status": "active"
                        });
                        match kv.put(&pairwise_did, serde_json::to_vec(&connection).unwrap().into()).await {
                            Ok(_) => {
                                // Also register in target_id_map for message routing
                                    let target_id = crate::logic::compute_target_id(&pairwise_did, &store.data().shared.house_salt);
                                    {
                                        let mut map = store.data().shared.target_id_map.write().await;
                                        map.insert(target_id.clone(), pairwise_did.clone());
                                    }
                                tracing::info!("🤝 Connection registered: {} (target: {})", pairwise_did, target_id);
                                Ok(true)
                            },
                            Err(e) => Err(format!("KV store error: {}", e)),
                        }
                    } else {
                        Err("connections_kv not available".into())
                    };
                    let _ = resp.send(result);
                },
                VaultCommand::ListConnections { resp } => {
                    let mut connections = Vec::new();
                    if let Some(kv) = store.data().shared.kv_stores.as_ref()
                        .and_then(|m| m.get("connections_kv"))
                    {
                        if let Ok(mut keys) = kv.keys().await {
                            use futures::StreamExt;
                            while let Some(Ok(key)) = keys.next().await {
                                connections.push(key);
                            }
                        }
                    }
                    let _ = resp.send(connections);
                },
                VaultCommand::RevokeConnection { pairwise_did, resp } => {
                    let result = if let Some(kv) = store.data().shared.kv_stores.as_ref()
                        .and_then(|m| m.get("connections_kv"))
                    {
                        match kv.delete(&pairwise_did).await {
                            Ok(_) => {
                                // Remove from target_id_map
                                let target_id = crate::logic::compute_target_id(&pairwise_did, &store.data().shared.house_salt);
                                {
                                    let mut map = store.data().shared.target_id_map.write().await;
                                    map.remove(&target_id);
                                }
                                tracing::info!("❌ Connection revoked: {}", pairwise_did);
                                Ok(true)
                            },
                            Err(e) => Err(format!("KV delete error: {}", e)),
                        }
                    } else {
                        Err("connections_kv not available".into())
                    };
                    let _ = resp.send(result);
                },
            }
        }
    });
}
