use std::sync::Arc;
use wasmtime::{Engine, component::{Component, Linker}};
use tokio::sync::mpsc::Receiver;

use crate::shared_state::{HostState, WebauthnSharedState};
use crate::commands::ContactStoreCommand;
use crate::bindings::contact_store_bindgen;
use super::create_store;

// 2b. Contact Store Loop Task
pub fn spawn_contact_store_loop(
    engine: Engine,
    shared: Arc<WebauthnSharedState>,
    contact_comp: Component,
    linker: Linker<HostState>,
    mut contact_rx: Receiver<ContactStoreCommand>,
) {
    tokio::spawn(async move {
        let mut store = create_store(&engine, shared);
        let inst = linker.instantiate_async(&mut store, &contact_comp).await.expect("Contact Store init failed");
        store.data_mut().contact_store = Some(inst);
        tracing::info!("📇 Contact Store loop started");
        
        while let Some(cmd) = contact_rx.recv().await {
            let inst_opt = store.data().contact_store.clone();
            match cmd {
                ContactStoreCommand::StoreContact { did_doc, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        // Types are shared via `with:` in bindgen — no mapping needed
                        if let Ok(client) = contact_store_bindgen::ContactStoreComponent::new(&mut store, &inst) {
                            let iface = client.sovereign_gateway_contact_store();
                            if let Ok(res) = iface.call_store_contact(&mut store, &did_doc).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(res); }
                            }
                        }
                        if resp_opt.is_some() {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Err("Contact StoreContact failed".into())); }
                        }
                    } else {
                        if let Some(r) = resp_opt.take() { let _ = r.send(Err("Contact Store component not loaded".into())); }
                    }
                },
                ContactStoreCommand::GetContact { did, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(client) = contact_store_bindgen::ContactStoreComponent::new(&mut store, &inst) {
                            let iface = client.sovereign_gateway_contact_store();
                            if let Ok(result) = iface.call_get_contact(&mut store, &did).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(result); }
                            }
                        }
                        if resp_opt.is_some() {
                            if let Some(r) = resp_opt.take() { let _ = r.send(None); }
                        }
                    } else {
                        if let Some(r) = resp_opt.take() { let _ = r.send(None); }
                    }
                },
                ContactStoreCommand::ListContacts { resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(client) = contact_store_bindgen::ContactStoreComponent::new(&mut store, &inst) {
                            let iface = client.sovereign_gateway_contact_store();
                            if let Ok(docs) = iface.call_list_contacts(&mut store).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(docs); }
                            }
                        }
                        if resp_opt.is_some() {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Vec::new()); }
                        }
                    } else {
                        if let Some(r) = resp_opt.take() { let _ = r.send(Vec::new()); }
                    }
                },
                ContactStoreCommand::DeleteContact { did, resp } => {
                    let mut resp_opt = Some(resp);
                    if let Some(inst) = inst_opt {
                        if let Ok(client) = contact_store_bindgen::ContactStoreComponent::new(&mut store, &inst) {
                            let iface = client.sovereign_gateway_contact_store();
                            if let Ok(res) = iface.call_delete_contact(&mut store, &did).await {
                                if let Some(r) = resp_opt.take() { let _ = r.send(res); }
                            }
                        }
                        if resp_opt.is_some() {
                            if let Some(r) = resp_opt.take() { let _ = r.send(Err("Contact DeleteContact failed".into())); }
                        }
                    } else {
                        if let Some(r) = resp_opt.take() { let _ = r.send(Err("Contact Store component not loaded".into())); }
                    }
                },
            }
        }
    });
}
