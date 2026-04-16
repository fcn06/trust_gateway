use std::sync::Arc;
use wasmtime::{Engine, component::{Component, Linker}};
use tokio::sync::mpsc::Receiver;

use crate::shared_state::{HostState, WebauthnSharedState};
use crate::commands::AclCommand;
use crate::bindings::acl_bindgen;
use super::create_store;

// 2. ACL Loop Task
pub fn spawn_acl_loop(
    engine: Engine,
    shared: Arc<WebauthnSharedState>,
    acl_comp: Component,
    linker: Linker<HostState>,
    mut acl_rx: Receiver<AclCommand>,
) {
    tokio::spawn(async move {
        let mut store = create_store(&engine, shared);
        let inst = linker.instantiate_async(&mut store, &acl_comp).await.expect("ACL Store init failed");
        store.data_mut().acl = Some(inst);
        
        while let Some(cmd) = acl_rx.recv().await {
            let inst_opt = store.data().acl.clone();
            match cmd {
                AclCommand::UpdatePolicy { owner, policy, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        let mut resp_sent = false;
                        if let Ok(acl_client) = acl_bindgen::AclStore::new(&mut store, &inst) {
                            let acl_iface = acl_client.sovereign_gateway_acl();
                            if let Ok(res) = acl_iface.call_update_policy(&mut store, &owner, &policy).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(res); }
                                resp_sent = true;
                            }
                        }
                        if !resp_sent {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Err("ACL UpdatePolicy failed".into())); }
                        }
                    } else {
                        if let Some(r) = resp_opt.take() { let _ = r.send(Err("ACL component not loaded".into())); }
                    }
                },
                AclCommand::GetPolicies { owner, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(acl_client) = acl_bindgen::AclStore::new(&mut store, &inst) {
                            let acl_iface = acl_client.sovereign_gateway_acl();
                            if let Ok(policies) = acl_iface.call_get_policies(&mut store, &owner).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(policies); }
                            } else {
                                    if let Some(r) = resp_opt.take() { let _ = r.send(Vec::new()); }
                            }
                        } else {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Vec::new()); }
                        }
                    } else {
                        if let Some(r) = resp_opt.take() { let _ = r.send(Vec::new()); }
                    }
                },
                AclCommand::CheckPermission { owner, subject, perm, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(acl_client) = acl_bindgen::AclStore::new(&mut store, &inst) {
                            let acl_iface = acl_client.sovereign_gateway_acl();
                            // Map permission from host world to component world
                            let perm_comp = match perm {
                                crate::sovereign::gateway::common_types::Permission::Chat => acl_bindgen::sovereign::gateway::common_types::Permission::Chat,
                                crate::sovereign::gateway::common_types::Permission::Discovery => acl_bindgen::sovereign::gateway::common_types::Permission::Discovery,
                                crate::sovereign::gateway::common_types::Permission::Appointment => acl_bindgen::sovereign::gateway::common_types::Permission::Appointment,
                                crate::sovereign::gateway::common_types::Permission::Payment => acl_bindgen::sovereign::gateway::common_types::Permission::Payment,
                                crate::sovereign::gateway::common_types::Permission::Agent => acl_bindgen::sovereign::gateway::common_types::Permission::Agent,
                            };
                            if let Ok(res) = acl_iface.call_check_permission(&mut store, &owner, &subject, perm_comp).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(res); }
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(false); }
                },
            }
        }
    });
}
