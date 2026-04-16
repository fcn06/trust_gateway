//! Identity WIT interface bindings.
//!
//! Implements the `sovereign:gateway/identity` interface for WebAuthn authentication.
//!
//! Note: The handler bindings currently use placeholder implementations.
//! Full WebAuthn logic flows remain in main.rs and are called via HTTP handlers.

use anyhow::Result;
use tokio::sync::oneshot;
use wasmtime::component::Linker;

use crate::commands::IdentityCommand;
use crate::shared_state::HostState;

/// Bind all identity interface functions to the linker.
pub fn bind_identity_interface(linker: &mut Linker<HostState>) -> Result<()> {
    let mut identity_linker = linker.instance("sovereign:gateway/identity")?;

    identity_linker.func_wrap_async("authenticate", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.identity_cmd_tx.send(IdentityCommand::Authenticate { id, resp: tx }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Identity task terminated")),
            }
        }))
    })?;

    // Registration and login WIT bindings - placeholder implementations
    // Full flows are handled via HTTP endpoints in main.rs
    identity_linker.func_wrap_async("start-registration", |_caller, (username,): (String,)| {
        Box::new(Box::pin(async move {
            tracing::debug!("🔐 [WIT] start-registration called for: {}", username);
            // Return placeholder - actual logic via HTTP /api/register/start
            Ok(("use_http_endpoint".to_string(),))
        }))
    })?;

    identity_linker.func_wrap_async("finish-registration", |_caller, (_session_id, _response): (String, String)| {
        Box::new(Box::pin(async move {
            tracing::debug!("🔐 [WIT] finish-registration called");
            // Return placeholder - actual logic via HTTP /api/register/finish
            Ok((false,))
        }))
    })?;

    identity_linker.func_wrap_async("start-login", |_caller, (username,): (String,)| {
        Box::new(Box::pin(async move {
            tracing::debug!("🔐 [WIT] start-login called for: {}", username);
            // Return placeholder - actual logic via HTTP /api/login/start
            Ok(("use_http_endpoint".to_string(),))
        }))
    })?;

    identity_linker.func_wrap_async("finish-login", |_caller, (_session_id, _response): (String, String)| {
        Box::new(Box::pin(async move {
            tracing::debug!("🔐 [WIT] finish-login called");
            // Return placeholder - actual logic via HTTP /api/login/finish
            Ok(("use_http_endpoint".to_string(),))
        }))
    })?;

    // Blueprint: Global login via NATS
    identity_linker.func_wrap_async("process-global-login", |caller, (assertion,): (Vec<u8>,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.identity_cmd_tx.send(IdentityCommand::ProcessGlobalLogin { 
                assertion, 
                resp: tx 
            }).await;
            match rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("Identity task terminated")),
            }
        }))
    })?;

    Ok(())
}
