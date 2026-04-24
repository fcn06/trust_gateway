use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use crate::api;
use crate::types::{ContactRequest, ConnectionPolicy};

#[component]
pub fn ApprovedContactsSection(
    base_url: String, 
    token: String, 
) -> impl IntoView {
    let (trigger, set_trigger) = signal(0);
    let (requests, set_requests) = signal(Vec::<ContactRequest>::new());
    let (policies, set_policies) = signal(Vec::<ConnectionPolicy>::new());
    
    // Enrichment state
    let (enrich_did, set_enrich_did) = signal(Option::<String>::None);
    let (enrich_alias, set_enrich_alias) = signal(String::new());

    let base_url = store_value(base_url);
    let token = store_value(token);
    
    Effect::new(move |_| {
        let ab = base_url.get_value();
        let tt = token.get_value();
        let _ = trigger.get();
        spawn_local(async move {
            if let Ok(list) = api::get_contact_requests(&ab, tt.clone()).await {
                let approved: Vec<_> = list.into_iter().filter(|r| r.status.to_lowercase() == "accepted").collect();
                set_requests.set(approved);
            }
            if let Ok(pols) = api::get_policies(&ab, tt).await {
                set_policies.set(pols);
            }
        });
    });

    view! {
        <div class="mt-8 space-y-4">
            <h3 class="text-xl font-bold text-white">"Approved Contacts"</h3>
            <div class="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden shadow-2xl">
                <div class="p-4 border-b border-slate-700 flex justify-between items-center">
                    <h3 class="text-lg font-semibold">"Contacts Directory"</h3>
                    <button 
                        on:click=move |_| set_trigger.update(|n| *n += 1)
                        class="text-xs text-blue-400 hover:text-blue-300"
                    >
                        "Refresh"
                    </button>
                </div>
                <Show 
                    when=move || !requests.get().is_empty()
                    fallback=move || view! {
                        <div class="p-8 text-center text-slate-500 italic">
                            "No approved contacts found."
                        </div>
                    }
                >
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-4">
                        <For
                            each=move || requests.get()
                            key=|r| r.id.clone()
                            children=move |req| {
                                let contact_did = req.sender_did.clone();
                                
                                let did_short = if contact_did.len() > 18 {
                                    format!("{}...{}", &contact_did[..10], &contact_did[contact_did.len()-4..])
                                } else {
                                    contact_did.clone()
                                };
                                let cd_copy = contact_did.clone();
                                let cd_title = contact_did.clone();
                                let cd_for_alias = contact_did.clone();
                                let cd_for_enrich = contact_did.clone();
                                
                                view! {
                                    <div class="p-4 bg-slate-900 border border-slate-700 rounded-xl hover:border-slate-500 transition-colors flex flex-col gap-3">
                                        <div class="flex justify-between items-start">
                                            <div class="flex flex-col">
                                                <span class="text-lg font-bold text-white truncate max-w-[150px]">
                                                    {
                                                        let cd = cd_for_alias.clone();
                                                        move || {
                                                            policies.get().iter()
                                                                .find(|p| p.did == cd)
                                                                .map(|p| p.alias.clone())
                                                                .unwrap_or_else(|| "Unknown Contact".to_string())
                                                        }
                                                    }
                                                </span>
                                                <span class="text-[10px] text-slate-500 font-mono">{did_short}</span>
                                            </div>
                                            <button 
                                                on:click=move |_| {
                                                    if let Some(win) = web_sys::window() {
                                                        let _ = win.navigator().clipboard().write_text(&cd_copy);
                                                    }
                                                }
                                                class="text-slate-500 hover:text-slate-300 bg-slate-800 p-1 rounded text-[10px]"
                                                title=cd_title
                                            >
                                                "Copy"
                                            </button>
                                        </div>
                                        
                                        <button 
                                            on:click=move |_| {
                                                let current_alias = policies.get().iter()
                                                    .find(|p| p.did == cd_for_enrich)
                                                    .map(|p| p.alias.clone())
                                                    .unwrap_or_else(|| "Unknown Contact".to_string());
                                                set_enrich_did.set(Some(cd_for_enrich.clone()));
                                                set_enrich_alias.set(current_alias);
                                            }
                                            class="w-full py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs font-bold transition-all"
                                        >
                                            "ENRICH"
                                        </button>
                                    </div>
                                }
                            }
                        />
                    </div>
                </Show>
            </div>

            <Show when=move || enrich_did.get().is_some()>
                <div class="mt-4 p-6 bg-slate-800 rounded-2xl border border-blue-500/50 space-y-4 shadow-2xl animate-in zoom-in duration-200">
                    <div class="flex justify-between items-center">
                        <h3 class="text-lg font-bold text-blue-300">"Enrich Contact Metadata"</h3>
                        <button on:click=move |_| set_enrich_did.set(None) class="text-slate-500 hover:text-white text-xl">"×"</button>
                    </div>

                    <div class="p-3 bg-slate-900 rounded border border-slate-700">
                        <p class="text-[10px] text-slate-500 uppercase font-bold">"Contact DID"</p>
                        <p class="text-[10px] font-mono text-blue-300 break-all">{move || enrich_did.get().unwrap_or_default()}</p>
                    </div>

                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Contact Alias"</label>
                        <input 
                            type="text" 
                            class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm focus:border-blue-500 outline-none"
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
                                        set_trigger.update(|n| *n += 1);
                                        set_enrich_did.set(None);
                                    },
                                    Err(e) => log::error!("Enrichment save failed: {}", e),
                                }
                            });
                        }
                        class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 py-2 rounded font-bold transition-all"
                    >
                        "Save Alias"
                    </button>
                </div>
            </Show>
        </div>
    }
}
