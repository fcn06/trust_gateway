//! Vault WIT interface bindings.
//!
//! Implements the `sovereign:gateway/vault` interface by proxying commands
//! to the Vault Wasm component via channels.

use anyhow::Result;
use tokio::sync::oneshot;
use wasmtime::component::Linker;

use crate::commands::VaultCommand;
use crate::shared_state::HostState;

/// Bind all vault interface functions to the linker.
pub fn bind_vault_interface(linker: &mut Linker<HostState>) -> Result<()> {
    let mut vault_linker = linker.instance("sovereign:gateway/vault")?;

    vault_linker.func_wrap_async("create-identity", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::CreateIdentity(id.clone(), tx)).await;
            match rx.await {
                Ok(did) => Ok((did,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("sign-message", |caller, (did, msg): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::SignMessage { did, msg, resp: tx }).await;
            match rx.await {
                Ok(res) => match res {
                    Ok(sig) => Ok((sig,)),
                    Err(e) => Err(anyhow::anyhow!(e)),
                },
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("get-active-did", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(id, tx)).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("pack-signed", |caller, (s, r, p): (String, String, String)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::PackSigned { sender: s, receiver: r, payload: p, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("verify-signed", |caller, (env,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::VerifySigned { envelope: env, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("list-identities", |caller, (user_id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id, tx)).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("resolve-did-to-user-id", |caller, (did,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::ResolveDid { did, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res.unwrap_or_default(),)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("set-active-did", |caller, (user_id, did): (String, String)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::SetActiveDid(user_id, did, tx)).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("get-hmac-secret", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            
            // ACL component passes DID map key as user_id. Resolve to actual user_id if needed.
            let user_id = if id.starts_with("did:") {
                let (tx, rx) = oneshot::channel();
                let _ = shared.vault_cmd_tx.send(VaultCommand::ResolveDid { did: id.clone(), resp: tx }).await;
                match rx.await {
                    Ok(Some(uid)) => uid,
                    _ => {
                        tracing::warn!("⚠️ [HMAC] Failed to resolve DID {} to user_id", id);
                        id
                    }
                }
            } else {
                id
            };

            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::GetHmacSecret { user_id, resp: tx }).await;
            match rx.await {
                Ok(res) => match res {
                    Ok(secret) => Ok((secret,)),
                    Err(_) => Ok((Vec::new(),)),
                },
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    // Master Seed functions
    vault_linker.func_wrap_async("generate-master-seed", |caller, (user_id, derivation_path): (String, String)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::GenerateMasterSeed { user_id, derivation_path, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("derive-link-nkey", |caller, (user_id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::DeriveLinkNkey { user_id, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("unlock-vault", |caller, (user_id, derivation_path): (String, String)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::UnlockVault { user_id, derivation_path, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("is-unlocked", |caller, (user_id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::IsUnlocked { user_id, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("set-recovery-secret", |caller, (user_id, nickname, secret): (String, String, String)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::SetRecoverySecret { user_id, nickname, secret, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("get-beacon-config", |caller, (user_id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::GetBeaconConfig { user_id, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("get-all-beacon-configs", |caller, (): ()| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::GetAllBeaconConfigs { resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Vault task terminated")),
            }
        }))
    })?;

    Ok(())
}
