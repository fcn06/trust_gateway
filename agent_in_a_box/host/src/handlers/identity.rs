//! Identity WIT interface bindings.
//!
//! NOTE: The Wasm identity_server component has been removed.
//! WebAuthn is handled natively by the Host (auth/logic.rs).
//! Registration/login WIT bindings delegate to the native auth logic.
//!
//! The `process-global-login` endpoint is disabled because the
//! global_ssi_portal has been removed from the architecture.

use anyhow::Result;
use wasmtime::component::Linker;

use crate::shared_state::HostState;

/// Bind all identity interface functions to the linker.
///
/// These are placeholder bindings that delegate to the Host's native
/// WebAuthn implementation. The Wasm identity_server is no longer used.
pub fn bind_identity_interface(linker: &mut Linker<HostState>) -> Result<()> {
    let mut identity_linker = linker.instance("sovereign:gateway/identity")?;

    // Registration and login WIT bindings — delegate to native Host logic
    identity_linker.func_wrap_async("start-registration", |caller, (username,): (String,)| {
        Box::new(Box::pin(async move {
            match crate::auth::start_registration_logic(&caller.data().shared, username, None).await {
                Ok((session_id, ccr)) => {
                    let res = serde_json::json!({ "session_id": session_id, "options": ccr });
                    Ok((serde_json::to_string(&res).unwrap(),))
                }
                Err(e) => {
                    tracing::error!("❌ start-registration error: {:?}", e);
                    Ok(("error".to_string(),))
                }
            }
        }))
    })?;

    identity_linker.func_wrap_async("finish-registration", |caller, (session_id, response): (String, String)| {
        Box::new(Box::pin(async move {
            match crate::auth::finish_registration_logic(caller.data().shared.clone(), session_id, response).await {
                Ok((success, _, _)) => Ok((success,)),
                Err(e) => {
                    tracing::error!("❌ finish-registration error: {:?}", e);
                    Ok((false,))
                }
            }
        }))
    })?;

    identity_linker.func_wrap_async("start-login", |caller, (username,): (String,)| {
        Box::new(Box::pin(async move {
            match crate::auth::start_login_logic(&caller.data().shared, username).await {
                Ok((session_id, rcr)) => {
                    let res = serde_json::json!({ "session_id": session_id, "options": rcr });
                    Ok((serde_json::to_string(&res).unwrap(),))
                }
                Err(e) => {
                    tracing::error!("❌ start-login error: {:?}", e);
                    Ok(("error".to_string(),))
                }
            }
        }))
    })?;

    identity_linker.func_wrap_async("finish-login", |caller, (session_id, response): (String, String)| {
        Box::new(Box::pin(async move {
            match crate::auth::finish_login_logic(caller.data().shared.clone(), session_id, response).await {
                Ok((token, _uid, _username, _cookie)) => Ok((token,)),
                Err(e) => {
                    tracing::error!("❌ finish-login error: {:?}", e);
                    Ok(("error".to_string(),))
                }
            }
        }))
    })?;

    // Global portal removed — process-global-login always returns error
    identity_linker.func_wrap_async("process-global-login", |_caller, (_assertion,): (Vec<u8>,)| {
        Box::new(Box::pin(async move {
            Ok((Err::<bool, String>("Global login not supported — global_ssi_portal has been removed".to_string()),))
        }))
    })?;

    // Authenticate — inlined (no longer routes through identity loop)
    identity_linker.func_wrap_async("authenticate", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::GetActiveDid(id.clone(), tx)).await;
            let nkey_seed = rx.await.unwrap_or_default();
            Ok((crate::sovereign::gateway::identity::AuthSession {
                user_id: id,
                nkey_seed,
            },))
        }))
    })?;

    Ok(())
}
