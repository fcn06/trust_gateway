use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use crate::api;
use crate::types::{ContactRequest, ConnectionPolicy};

#[component]
pub fn ApprovedContactsSection(
    base_url: String, 
    token: String, 
    policies: ReadSignal<Vec<ConnectionPolicy>>,
    refresh_trigger: ReadSignal<i32>,
    set_refresh_trigger: WriteSignal<i32>,
    active_did: ReadSignal<String>,
) -> impl IntoView {
    let (requests, set_requests) = signal(Vec::<ContactRequest>::new());
    
    // Enrichment state
    let (enrich_did, set_enrich_did) = signal(Option::<String>::None);
    let (enrich_alias, set_enrich_alias) = signal(String::new());

    let base_url = store_value(base_url);
    let token = store_value(token);
    
    Effect::new(move |_| {
        let ab = base_url.get_value();
        let tt = token.get_value();
        let _ = refresh_trigger.get();
        let active = active_did.get();
        spawn_local(async move {
            if let Ok(list) = api::get_contact_requests(&ab, tt).await {
                let approved: Vec<_> = list.into_iter()
                    .filter(|r| r.status.to_lowercase() == "accepted" && (active.is_empty() || r.owner_did == active))
                    .collect();
                set_requests.set(approved);
            }
        });
    });

    view! {
        <div class="space-y-4">
            <div class="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden shadow-xl">
                <div class="p-4 border-b border-slate-700 flex justify-between items-center">
                    <div>
                        <h3 class="text-lg font-semibold text-white">"Connected Contacts"</h3>
                        <p class="text-xs text-slate-500 mt-0.5">"People connected to your active profile."</p>
                    </div>
                    <button 
                        on:click=move |_| set_refresh_trigger.update(|n| *n += 1)
                        class="text-xs text-blue-400 hover:text-blue-300"
                    >
                        "Refresh"
                    </button>
                </div>
                <Show 
                    when=move || !requests.get().is_empty()
                    fallback=move || view! {
                        <div class="p-8 text-center text-slate-500">
                            <p class="text-sm italic">"No contacts yet for this profile."</p>
                            <p class="text-xs mt-1 text-slate-600">"Send a connection request from the Requests tab."</p>
                        </div>
                    }
                >
                    // Compact row-based list
                    <div class="divide-y divide-slate-700/50">
                        <For
                            each=move || requests.get()
                            key=|r| r.id.clone()
                            children=move |req| {
                                let contact_did = req.sender_did.clone();
                                let cd_copy = contact_did.clone();
                                let cd_title = contact_did.clone();
                                let cd_for_alias = contact_did.clone();
                                let cd_for_enrich = contact_did.clone();
                                
                                let did_short = if contact_did.len() > 18 {
                                    format!("{}...{}", &contact_did[..10], &contact_did[contact_did.len()-4..])
                                } else {
                                    contact_did.clone()
                                };

                                view! {
                                    <div class="flex items-center gap-3 px-4 py-2.5 hover:bg-slate-700/30 transition-colors group">
                                        // Avatar circle
                                        <div class="w-8 h-8 rounded-full bg-blue-900/40 border border-blue-500/20 flex items-center justify-center text-xs font-bold text-blue-300 shrink-0">
                                            {
                                                let cd = cd_for_alias.clone();
                                                move || {
                                                    let name = policies.get().iter()
                                                        .find(|p| p.did == cd)
                                                        .map(|p| p.alias.clone())
                                                        .unwrap_or_else(|| "?".to_string());
                                                    name.chars().next().unwrap_or('?').to_uppercase().to_string()
                                                }
                                            }
                                        </div>
                                        
                                        // Name + DID
                                        <div class="flex-1 min-w-0">
                                            <div class="font-semibold text-sm text-white truncate">
                                                {
                                                    let cd = cd_for_alias.clone();
                                                    move || {
                                                        policies.get().iter()
                                                            .find(|p| p.did == cd)
                                                            .map(|p| p.alias.clone())
                                                            .unwrap_or_else(|| "Unknown Contact".to_string())
                                                    }
                                                }
                                            </div>
                                            <div class="text-[10px] text-slate-500 font-mono truncate">{did_short}</div>
                                        </div>
                                        
                                        // Actions (visible on hover)
                                        <div class="flex items-center gap-1.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                                            <button
                                                on:click=move |_| {
                                                    if let Some(win) = web_sys::window() {
                                                        let _ = win.navigator().clipboard().write_text(&cd_copy);
                                                    }
                                                }
                                                class="text-[10px] text-slate-500 hover:text-slate-300 bg-slate-800 px-2 py-1 rounded border border-slate-700 transition-colors"
                                                title=cd_title
                                            >
                                                "Copy ID"
                                            </button>
                                            <button 
                                                on:click=move |_| {
                                                    let current_alias = policies.get().iter()
                                                        .find(|p| p.did == cd_for_enrich)
                                                        .map(|p| p.alias.clone())
                                                        .unwrap_or_else(|| "Unknown Contact".to_string());
                                                    set_enrich_did.set(Some(cd_for_enrich.clone()));
                                                    set_enrich_alias.set(current_alias);
                                                }
                                                class="text-[10px] text-blue-400 hover:text-blue-300 bg-blue-900/30 px-2 py-1 rounded border border-blue-500/20 transition-colors"
                                            >
                                                "Edit"
                                            </button>
                                            <button 
                                                on:click={
                                                    let req_id = req.id.clone();
                                                    move |_| {
                                                        let ab = base_url.get_value();
                                                        let tt = token.get_value();
                                                        let req_id = req_id.clone();
                                                        spawn_local(async move {
                                                            match api::delete_contact_request(&ab, req_id, tt).await {
                                                                Ok(_) => {
                                                                    set_refresh_trigger.update(|n| *n += 1);
                                                                },
                                                                Err(e) => log::error!("Failed to delete contact: {}", e),
                                                            }
                                                        });
                                                    }
                                                }
                                                class="text-[10px] text-red-400 hover:text-red-300 bg-red-900/20 px-2 py-1 rounded border border-red-500/20 transition-colors"
                                            >
                                                "Remove"
                                            </button>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </div>
                </Show>
            </div>

            // Enrich/Edit modal
            <Show when=move || enrich_did.get().is_some()>
                <div class="p-5 bg-slate-800 rounded-2xl border border-blue-500/50 space-y-4 shadow-2xl">
                    <div class="flex justify-between items-center">
                        <h3 class="text-lg font-bold text-blue-300">"Edit Contact"</h3>
                        <button on:click=move |_| set_enrich_did.set(None) class="text-slate-500 hover:text-white text-xl">"×"</button>
                    </div>

                    <div class="p-3 bg-slate-900 rounded border border-slate-700">
                        <p class="text-[10px] text-slate-500 uppercase font-bold">"Unique ID"</p>
                        <p class="text-[10px] font-mono text-blue-300 break-all">{move || enrich_did.get().unwrap_or_default()}</p>
                    </div>

                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Contact Name"</label>
                        <input 
                            type="text" 
                            class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:border-blue-500 outline-none"
                            prop:value=move || enrich_alias.get()
                            on:input=move |ev| set_enrich_alias.set(event_target_value(&ev))
                        />
                    </div>
                    
                    <button 
                        on:click=move |_| {
                            let did = enrich_did.get().unwrap_or_default();
                            let a = enrich_alias.get();
                            let tt = token.get_value();
                            let ab = base_url.get_value();
                            spawn_local(async move {
                                match api::enrich_identity(&ab, did, a, false, tt).await {
                                    Ok(_) => {
                                        set_refresh_trigger.update(|n| *n += 1);
                                        set_enrich_did.set(None);
                                    },
                                    Err(e) => log::error!("Enrichment save failed: {}", e),
                                }
                            });
                        }
                        class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 py-2 rounded font-bold transition-all"
                    >
                        "Save Contact"
                    </button>
                </div>
            </Show>
        </div>
    }
}
