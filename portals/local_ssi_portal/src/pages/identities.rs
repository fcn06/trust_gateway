//! Identities page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::EnrichedIdentity;

#[component]
pub fn Identities(
    base_url: String, 
    username: String, 
    token: String, 
    user_id: String, 
    identities: ReadSignal<Vec<EnrichedIdentity>>, 
    set_identities: WriteSignal<Vec<EnrichedIdentity>>,
    active_did: ReadSignal<String>,
    set_active_did: WriteSignal<String>,
    refresh_trigger: ReadSignal<i32>,
    set_refresh_trigger: WriteSignal<i32>,
    policies: ReadSignal<Vec<crate::types::ConnectionPolicy>>,
) -> impl IntoView {
    let (status_message, set_status_message) = signal(Option::<(String, bool)>::None);
    let (published_dids, set_published_dids) = signal(Vec::<String>::new());

    let base_url = store_value(base_url);
    let token = store_value(token);
    let tt = token.get_value();

    let (enrich_did, set_enrich_did) = signal(Option::<String>::None);
    let (enrich_alias, set_enrich_alias) = signal(String::new());
    let (enrich_is_institutional, set_enrich_is_institutional) = signal(false);

    // Initial load and refresh handling
    let user_id_for_published = user_id.clone();
    let ab_for_published = base_url.get_value();
    Effect::new(move |_| {
        let _ = refresh_trigger.get();
        let uid = user_id_for_published.clone();
        let ab = ab_for_published.clone();
        spawn_local(async move {
            match api::get_published_dids(&ab, uid).await {
                Ok(dids) => set_published_dids.set(dids),
                Err(e) => log::warn!("Failed to load published DIDs: {}", e),
            }
        });
    });

    let on_generate = move |_| {
        let tt = token.get_value();
        let ab = base_url.get_value();
        spawn_local(async move {
            match api::create_identity(&ab, tt).await {
                Ok(_) => {
                    log::info!("Identity generated");
                    set_refresh_trigger.update(|n| *n += 1);
                },
                Err(e) => log::error!("Failed to generate identity: {}", e),
            }
        });
    };

    // Web identity functionality has been moved to SetupWebIdentity component

    view! {
        <div class="space-y-6 text-white">
            <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <h2 class="text-2xl font-bold text-white">"Manage Identities"</h2>
                <div class="flex flex-wrap gap-2">
                    <button
                        on:click=move |_| set_refresh_trigger.update(|n| *n += 1)
                        class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-sm border border-slate-600">
                        "Refresh"
                    </button>
                    <button 
                        on:click=on_generate
                        class="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-lg shadow-blue-600/20">
                        "Create New Identity"
                    </button>
                    <button 
                        on:click=move |_| {
                            if let Some(win) = web_sys::window() {
                                if !win.confirm_with_message("Are you sure you want to publish your identity to the public DHT directory? This will make your DID discoverable by others.").unwrap_or(false) {
                                    return;
                                }
                            }
                            let uid = user_id.clone();
                            let ab = base_url.get_value();
                            let current_active = active_did.get();
                            set_status_message.set(None);
                            spawn_local(async move {
                                match api::publish_did(&ab, uid).await {
                                    Ok(_) => {
                                        set_status_message.set(Some(("✅ Identity published to DHT successfully!".to_string(), true)));
                                        if !current_active.is_empty() {
                                            set_published_dids.update(|v| {
                                                if !v.contains(&current_active) {
                                                    v.push(current_active.clone());
                                                }
                                            });
                                        }
                                    },
                                    Err(e) => set_status_message.set(Some((format!("❌ Publish failed: {}", e), false))),
                                }
                            });
                        }
                        class="bg-purple-600 hover:bg-purple-500 px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-lg shadow-purple-600/20">
                        "Publish to Public Directory"
                    </button>
                </div>
            </div>
            
            <Show when=move || status_message.get().is_some()>
                {move || {
                    let (msg, is_success) = status_message.get().unwrap_or_default();
                    let class = if is_success {
                        "p-3 rounded-lg bg-green-900/30 border border-green-500/50 text-green-400 text-sm"
                    } else {
                        "p-3 rounded-lg bg-red-900/30 border border-red-500/50 text-red-400 text-sm"
                    };
                    view! { <div class=class>{msg}</div> }
                }}
            </Show>
            
            {move || {
                let list = identities.get();
                if list.is_empty() {
                    return view! { <div class="p-8 text-center text-slate-500 italic">"No identities found. Generate one above."</div> }.into_any();
                }
                let active_did = active_did;
                let token = token;
                let refresh_trigger = refresh_trigger;
                view! {
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                        <For
                            each=move || list.clone()
                            key=|item| item.did.clone()
                            children=move |item| {
                                let did = item.did.clone();
                                let alias = item.alias.clone();
                                let tt = token.get_value();
                                let on_activate = {
                                    let d = did.clone();
                                    let ab = base_url.get_value();
                                    move |_| {
                                        let d = d.clone();
                                        let ab = ab.clone();
                                        let tt = tt.clone();
                                        spawn_local(async move {
                                            if let Ok(_) = api::activate_identity(&ab, d, tt).await {
                                                set_refresh_trigger.update(|n| *n += 1);
                                            }
                                        });
                                    }
                                };
                                let d_for_show1 = did.clone();
                                let d_for_show2 = did.clone();
                                let d_for_enrich = did.clone();
                                let a_for_enrich = alias.clone();
                                let is_inst_for_show = item.is_institutional;
                                // Truncate DID for display: first 10 chars ... last 4 chars
                                let did_short = if did.len() > 18 {
                                    format!("{}...{}", &did[..10], &did[did.len()-4..])
                                } else {
                                    did.clone()
                                };
                                view! {
                                    <div class="p-4 bg-slate-900 rounded-xl border border-slate-800 flex flex-col gap-4 shadow-lg hover:border-slate-600 transition-colors">
                                        // Top row: Alias + Truncated DID
                                        <div class="flex justify-between items-start gap-2">
                                            <h3 class="text-xl font-bold text-white truncate">{alias}</h3>
                                            <div class="group relative">
                                                <button class="text-xs text-slate-500 hover:text-blue-400 transition-colors cursor-pointer flex items-center gap-1">
                                                    "Advanced Details"
                                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                                                </button>
                                                <div class="opacity-0 invisible group-hover:opacity-100 group-hover:visible absolute right-0 top-full mt-2 bg-slate-800 border border-slate-600 rounded-lg shadow-xl p-3 z-50 transition-all">
                                                    <div class="text-[10px] text-slate-400 mb-1">"Cryptographic Identifier:"</div>
                                                    <div class="flex items-center gap-2">
                                                        <span class="font-mono text-xs text-slate-300 whitespace-nowrap">{did_short}</span>
                                                        {
                                                            let d_copy = did.clone();
                                                            let tooltip = did.clone();
                                                            view! {
                                                                <button 
                                                                    on:click=move |_| {
                                                                        let d = d_copy.clone();
                                                                        if let Some(win) = web_sys::window() {
                                                                            let nav = win.navigator();
                                                                            let clip = nav.clipboard();
                                                                            let _ = clip.write_text(&d);
                                                                        }
                                                                    }
                                                                    class="text-blue-400 hover:text-blue-300 p-1 bg-blue-900/30 rounded"
                                                                    title=tooltip
                                                                >
                                                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                                                                </button>
                                                            }
                                                        }
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        // Status badges — flex-wrap so they don't overflow
                                        <div class="flex flex-wrap gap-2">
                                            <Show when=move || is_inst_for_show>
                                                <span class="px-3 py-1 bg-amber-900/30 text-amber-500 text-[10px] rounded-full border border-amber-500/50 font-bold">"INSTITUTIONAL"</span>
                                            </Show>
                                            <Show 
                                                when=move || d_for_show1.clone() == active_did.get()
                                                fallback=move || {
                                                    let on_act = on_activate.clone();
                                                    view! { 
                                                        <button 
                                                            on:click=move |_| on_act(())
                                                            class="px-3 py-1 bg-blue-900/30 text-blue-400 text-[10px] rounded-full border border-blue-500/50 font-bold hover:bg-blue-900/50 transition-all cursor-pointer">
                                                            "ACTIVATE"
                                                        </button>
                                                    }
                                                }
                                            >
                                                <span class="px-3 py-1 bg-emerald-900/30 text-emerald-500 text-[10px] rounded-full border border-emerald-500/50 font-bold">"ACTIVE"</span>
                                            </Show>
                                            
                                            <Show when=move || published_dids.get().contains(&d_for_show2)>
                                                <span class="px-3 py-1 bg-purple-900/30 text-purple-500 text-[10px] rounded-full border border-purple-500/50 font-bold">"PUBLISHED"</span>
                                            </Show>
                                        </div>

                                        // Enrich button — full width
                                        <button 
                                            on:click=move |_| {
                                                set_enrich_did.set(Some(d_for_enrich.clone()));
                                                set_enrich_alias.set(a_for_enrich.clone());
                                                set_enrich_is_institutional.set(is_inst_for_show);
                                            }
                                            class="w-full py-2 bg-blue-600 hover:bg-blue-500 rounded-lg font-bold text-sm transition-all shadow-lg shadow-blue-600/20"
                                            title="Add a custom alias to easily identify this DID"
                                        >
                                            "Add details"
                                        </button>
                                    </div>
                                }
                            }/>
                    </div>
                }.into_any()
            }}

            // Approved Contacts Section (inserted below Identity cards)
            {
                let ab = base_url.get_value();
                let tt = token.get_value();
                view! {
                    <div class="h-px bg-slate-700 w-full my-4"></div>
                    <crate::pages::ApprovedContactsSection 
                        base_url=ab 
                        token=tt 
                        policies=policies 
                        refresh_trigger=refresh_trigger 
                        set_refresh_trigger=set_refresh_trigger
                    />
                }
            }

            <Show when=move || enrich_did.get().is_some()>
                <div class="mt-8 p-6 bg-slate-800 rounded-2xl border border-blue-500/50 space-y-4 shadow-2xl animate-in zoom-in duration-200">
                    <div class="flex justify-between items-center">
                        <h3 class="text-lg font-bold text-blue-300">"Enrich Identity Metadata"</h3>
                        <button on:click=move |_| set_enrich_did.set(None) class="text-slate-500 hover:text-white text-xl transition-colors">"×"</button>
                    </div>

                    <div class="p-3 bg-slate-900 rounded border border-slate-700">
                        <p class="text-[10px] text-slate-500 uppercase font-bold">"DID"</p>
                        <p class="text-[10px] font-mono text-blue-300 break-all">{move || enrich_did.get().unwrap_or_default()}</p>
                    </div>

                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Alias"</label>
                        <input 
                            type="text" 
                            class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm focus:border-blue-500 outline-none transition-all"
                            prop:value=move || enrich_alias.get()
                            on:input=move |ev| set_enrich_alias.set(event_target_value(&ev))
                        />
                    </div>
                    
                    <button 
                        on:click=move |_| {
                            let did = match enrich_did.get() {
                                Some(d) => d,
                                None => return,
                            };
                            let a = enrich_alias.get();
                            let inst = enrich_is_institutional.get();
                            
                            let tt = token.get_value();
                            let ab = base_url.get_value();
                            spawn_local(async move {
                                match api::enrich_identity(&ab, did, a, inst, tt).await {
                                    Ok(_) => {
                                        set_refresh_trigger.update(|n| *n += 1);
                                        set_enrich_did.set(None);
                                    },
                                    Err(e) => log::error!("Enrichment save failed: {}", e),
                                }
                            });
                        }
                        class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 py-2 rounded font-bold transition-all shadow-lg shadow-blue-600/20"
                    >
                        "Save Alias"
                    </button>
                </div>
            </Show>
        </div>
    }
}
