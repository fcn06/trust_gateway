use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use async_nats::jetstream::kv::Store;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::shared_state::WebauthnSharedState;
use crate::commands::AclCommand;
use crate::sovereign::gateway::common_types::{ConnectionPolicy, Permission, ConnectionStatus};

// 2. Native ACL Loop Task (Replaces Wasm Component)
pub fn spawn_acl_loop(
    shared: Arc<WebauthnSharedState>,
    mut acl_rx: Receiver<AclCommand>,
) {
    tokio::spawn(async move {
        let store_opt = shared.kv_stores.as_ref().and_then(|m| m.get("acl").cloned());
        
        while let Some(cmd) = acl_rx.recv().await {
            match cmd {
                AclCommand::UpdatePolicy { owner, policy, resp } => {
                    if let Some(ref store) = store_opt {
                        let res = update_policy(store, &owner, policy).await;
                        let _ = resp.send(res);
                    } else {
                        let _ = resp.send(Err("ACL store not available".into()));
                    }
                },
                AclCommand::GetPolicies { owner, resp } => {
                    if let Some(ref store) = store_opt {
                        let policies = get_policies(store, &owner).await;
                        let _ = resp.send(policies);
                    } else {
                        let _ = resp.send(Vec::new());
                    }
                },
                AclCommand::CheckPermission { owner, subject, perm, resp } => {
                    if let Some(ref store) = store_opt {
                        let has_perm = check_permission(store, &owner, &subject, perm).await;
                        let _ = resp.send(has_perm);
                    } else {
                        let _ = resp.send(false);
                    }
                },
                AclCommand::DeletePolicy { owner, subject, resp } => {
                    if let Some(ref store) = store_opt {
                        let res = delete_policy(store, &owner, &subject).await;
                        let _ = resp.send(res);
                    } else {
                        let _ = resp.send(Err("ACL store not available".into()));
                    }
                },
            }
        }
    });
}

fn build_key(owner: &str, subject: &str) -> String {
    // JetStream keys cannot contain colons, using underscores
    format!("{}_{}", owner, subject).replace(":", "_")
}

async fn update_policy(store: &Store, owner: &str, policy: ConnectionPolicy) -> Result<bool, String> {
    let key = build_key(owner, &policy.did);
    let value = serde_json::to_vec(&policy).map_err(|e| e.to_string())?;
    
    store.put(&key, value.into()).await.map_err(|e| e.to_string())?;
    
    // Add to index
    let index_key = format!("{}_index", owner).replace(":", "_");
    let mut index: Vec<String> = if let Ok(Some(entry)) = store.get(&index_key).await {
        serde_json::from_slice(&entry).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    if !index.contains(&key) {
        index.push(key);
        let index_val = serde_json::to_vec(&index).unwrap();
        let _ = store.put(&index_key, index_val.into()).await;
    }

    Ok(true)
}

async fn get_policies(store: &Store, owner: &str) -> Vec<ConnectionPolicy> {
    let mut policies = Vec::new();
    let index_key = format!("{}_index", owner).replace(":", "_");
    
    if let Ok(Some(entry)) = store.get(&index_key).await {
        if let Ok(index) = serde_json::from_slice::<Vec<String>>(&entry) {
            for key in index {
                if let Ok(Some(val)) = store.get(&key).await {
                    if let Ok(policy) = serde_json::from_slice::<ConnectionPolicy>(&val) {
                        policies.push(policy);
                    }
                }
            }
        }
    }
    policies
}

async fn check_permission(store: &Store, owner: &str, subject: &str, perm: Permission) -> bool {
    let key = build_key(owner, subject);
    if let Ok(Some(val)) = store.get(&key).await {
        if let Ok(policy) = serde_json::from_slice::<ConnectionPolicy>(&val) {
            if policy.status != ConnectionStatus::Active {
                return false;
            }
            
            for p in &policy.permissions {
                if *p == perm {
                    return true;
                }
            }
        }
    }
    false
}

async fn delete_policy(store: &Store, owner: &str, subject: &str) -> Result<bool, String> {
    let key = build_key(owner, subject);
    
    // Delete the key from KV store
    let _ = store.delete(&key).await.map_err(|e| e.to_string())?;
    
    // Remove from index
    let index_key = format!("{}_index", owner).replace(":", "_");
    if let Ok(Some(entry)) = store.get(&index_key).await {
        if let Ok(mut index) = serde_json::from_slice::<Vec<String>>(&entry) {
            if index.contains(&key) {
                index.retain(|k| k != &key);
                let index_val = serde_json::to_vec(&index).unwrap();
                let _ = store.put(&index_key, index_val.into()).await.map_err(|e| e.to_string())?;
            }
        }
    }
    
    Ok(true)
}
