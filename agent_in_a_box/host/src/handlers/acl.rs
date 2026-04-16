//! ACL WIT interface bindings.
//!
//! Implements the `sovereign:gateway/acl` interface for access control policies.

use anyhow::Result;
use tokio::sync::oneshot;
use wasmtime::component::Linker;

use crate::commands::AclCommand;
use crate::shared_state::HostState;
use crate::sovereign::gateway::common_types::Permission;

/// Bind ACL interface functions to the linker.
pub fn bind_acl_interface(linker: &mut Linker<HostState>) -> Result<()> {
    let mut acl_linker = linker.instance("sovereign:gateway/acl")?;

    acl_linker.func_wrap_async("check-permission", |caller, (owner_did, subject, perm): (String, String, Permission)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            
            // DID-based ACLs: Use DID directly as owner (don't resolve to user_id)
            let user_id = owner_did;

            let (a_tx, a_rx) = oneshot::channel();
            // Map permission (identity mapping since same type)
            let perm_mapped = match perm {
                Permission::Chat => Permission::Chat,
                Permission::Discovery => Permission::Discovery,
                Permission::Appointment => Permission::Appointment,
                Permission::Payment => Permission::Payment,
            };

            let _ = shared.acl_cmd_tx.send(AclCommand::CheckPermission { 
                owner: user_id, 
                subject, 
                perm: perm_mapped, 
                resp: a_tx 
            }).await;
            
            match a_rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("ACL task terminated")),
            }
        }))
    })?;

    Ok(())
}
