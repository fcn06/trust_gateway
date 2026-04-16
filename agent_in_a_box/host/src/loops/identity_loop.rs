use std::sync::Arc;
use wasmtime::{Engine, component::{Component, Linker}};
use tokio::sync::mpsc::Receiver;

use crate::shared_state::{HostState, WebauthnSharedState};
use crate::commands::IdentityCommand;
use crate::bindings::identity_bindgen;
use super::create_store;

// 3. Identity Loop Task
pub fn spawn_identity_loop(
    engine: Engine,
    shared: Arc<WebauthnSharedState>,
    identity_comp: Component,
    linker: Linker<HostState>,
    mut identity_rx: Receiver<IdentityCommand>,
) {
    tokio::spawn(async move {
        let mut store = create_store(&engine, shared);
        let inst = linker.instantiate_async(&mut store, &identity_comp).await.expect("Identity init failed");
        store.data_mut().identity = Some(inst);
        
        while let Some(cmd) = identity_rx.recv().await {
            let inst_opt = store.data().identity.clone();
            match cmd {
                IdentityCommand::ProcessGlobalLogin { assertion, resp } => {
                        let mut resp_opt = Some(resp);
                        if let Some(inst) = inst_opt {
                            if let Ok(identity_client) = identity_bindgen::IdentityServer::new(&mut store, &inst) {
                                let identity_iface = identity_client.sovereign_gateway_identity();
                                match identity_iface.call_process_global_login(&mut store, &assertion).await {
                                    Ok(res) => { if let Some(r) = resp_opt.take() { let _ = r.send(res); } },
                                    Err(e) => { if let Some(r) = resp_opt.take() { let _ = r.send(Err(format!("WIT Error: {:?}", e))); } },
                                }
                            } else {
                                if let Some(r) = resp_opt.take() { let _ = r.send(Err("Failed to wrap Identity instance".into())); }
                            }
                        } else {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Err("Identity component not loaded".into())); }
                        }
                },
                IdentityCommand::Authenticate { id, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(identity_client) = identity_bindgen::IdentityServer::new(&mut store, &inst) {
                            let identity_iface = identity_client.sovereign_gateway_identity();
                            if let Ok(session) = identity_iface.call_authenticate(&mut store, &id).await {
                                if let Some(r) = resp_opt.take() { 
                                    let _ = r.send(crate::sovereign::gateway::identity::AuthSession {
                                        user_id: session.user_id,
                                        nkey_seed: session.nkey_seed,
                                    }); 
                                }
                            }
                        }
                    }
                    if let Some(r) = resp_opt.take() { let _ = r.send(crate::sovereign::gateway::identity::AuthSession { user_id: id, nkey_seed: "FALLBACK".to_string() }); }
                },
            }
        }
    });
}
