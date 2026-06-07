//! People — unified page combining profile selector, contacts, requests, and invitations.
//!
//! The active profile determines which contacts are shown. By embedding the
//! profile selector directly on this page, users always see the coupling.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use crate::api;

use crate::types::{EnrichedIdentity, ConnectionPolicy};
use crate::pages::{ContactRequestsSection, InvitationsSection};

#[component]
pub fn ContactsAndInvitations(
    base_url: String,
    token: String,
    identities: ReadSignal<Vec<EnrichedIdentity>>,
    refresh_trigger: ReadSignal<i32>,
    set_refresh_trigger: WriteSignal<i32>,
    policies: ReadSignal<Vec<ConnectionPolicy>>,
    active_did: ReadSignal<String>,
    set_active_did: WriteSignal<String>,
    set_active_section: WriteSignal<String>,
) -> impl IntoView {
    let (active_tab, set_active_tab) = signal("contacts".to_string());

    let base_url_a = base_url.clone();
    let base_url_b = base_url.clone();
    let base_url_c = base_url.clone();
    let token_a = token.clone();
    let token_b = token.clone();
    let token_c = token.clone();

    view! {
        <div class="max-w-[1400px] mx-auto w-full space-y-5">

            // ── Active Profile Selector ─────────────────────────────
            <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl p-3 flex flex-col sm:flex-row items-start sm:items-center gap-3 backdrop-blur-sm">
                <div class="flex items-center gap-2 text-sm text-slate-400 shrink-0">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2"></path>
                    </svg>
                    <span class="font-semibold">"Active Profile:"</span>
                </div>
                <select
                    prop:value=move || active_did.get()
                    on:change={
                        let base_url = base_url.clone();
                        let token = token.clone();
                        move |e| {
                            let val = event_target_value(&e);
                            let bu = base_url.clone();
                            let tok = token.clone();
                            spawn_local(async move {
                                if let Ok(_) = api::activate_identity(&bu, val.clone(), tok).await {
                                    set_active_did.set(val);
                                    set_refresh_trigger.update(|n| *n += 1);
                                }
                            });
                        }
                    }
                    class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white focus:ring-2 focus:ring-blue-500 outline-none min-w-0"
                >
                    <For
                        each=move || identities.get()
                        key=|id| id.did.clone()
                        children=move |identity| {
                            let did = identity.did.clone();
                            let did_for_check = did.clone();
                            let label = if identity.alias.is_empty() {
                                if did.len() > 20 {
                                    format!("{}...{}", &did[..10], &did[did.len()-4..])
                                } else {
                                    did.clone()
                                }
                            } else {
                                identity.alias.clone()
                            };
                            view! {
                                <option
                                    value=did
                                    selected=move || active_did.get() == did_for_check
                                >
                                    {label}
                                </option>
                            }
                        }
                    />
                </select>
                <button
                    on:click=move |_| {
                        let did = active_did.get();
                        if !did.is_empty() {
                            if let Some(win) = web_sys::window() {
                                let _ = win.navigator().clipboard().write_text(&did);
                            }
                        }
                    }
                    class="text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 px-3 py-1.5 rounded-lg transition-all shrink-0 flex items-center gap-1"
                >
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path>
                    </svg>
                    "Copy DID"
                </button>
                <button
                    on:click=move |_| set_active_section.set("manage_identities".to_string())
                    class="text-xs text-blue-400 hover:text-blue-300 border border-blue-500/30 hover:border-blue-400/50 px-3 py-1.5 rounded-lg transition-all shrink-0"
                >
                    "Manage Profiles"
                </button>
            </div>

            // ── Tab Bar ──────────────────────────────────────────────
            <div class="flex gap-1 bg-slate-800/60 p-1 rounded-xl border border-slate-700/60 backdrop-blur-sm">
                <button
                    on:click=move |_| set_active_tab.set("contacts".to_string())
                    class=move || {
                        let base = "flex-1 py-2 rounded-lg text-xs font-semibold transition-all duration-200 text-center";
                        if active_tab.get() == "contacts" {
                            format!("{} bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/25", base)
                        } else {
                            format!("{} text-slate-400 hover:text-white hover:bg-slate-700/50", base)
                        }
                    }
                >
                    "Contacts"
                </button>
                <button
                    on:click=move |_| set_active_tab.set("requests".to_string())
                    class=move || {
                        let base = "flex-1 py-2 rounded-lg text-xs font-semibold transition-all duration-200 text-center";
                        if active_tab.get() == "requests" {
                            format!("{} bg-gradient-to-r from-emerald-600 to-emerald-500 text-white shadow-lg shadow-emerald-500/25", base)
                        } else {
                            format!("{} text-slate-400 hover:text-white hover:bg-slate-700/50", base)
                        }
                    }
                >
                    "Requests"
                </button>
                <button
                    on:click=move |_| set_active_tab.set("invitations".to_string())
                    class=move || {
                        let base = "flex-1 py-2 rounded-lg text-xs font-semibold transition-all duration-200 text-center";
                        if active_tab.get() == "invitations" {
                            format!("{} bg-gradient-to-r from-purple-600 to-purple-500 text-white shadow-lg shadow-purple-500/25", base)
                        } else {
                            format!("{} text-slate-400 hover:text-white hover:bg-slate-700/50", base)
                        }
                    }
                >
                    "Invitations"
                </button>
            </div>

            // ── Tab Content ──────────────────────────────────────────
            <div>
                <Show when=move || active_tab.get() == "contacts">
                    <crate::pages::ApprovedContactsSection
                        base_url=base_url_a.clone()
                        token=token_a.clone()
                        policies=policies
                        refresh_trigger=refresh_trigger
                        set_refresh_trigger=set_refresh_trigger
                        active_did=active_did
                    />
                </Show>
                <Show when=move || active_tab.get() == "requests">
                    <ContactRequestsSection
                        base_url=base_url_b.clone()
                        token=token_b.clone()
                        identities=identities
                        refresh_trigger=refresh_trigger
                        set_refresh_trigger=set_refresh_trigger
                        policies=policies
                    />
                </Show>
                <Show when=move || active_tab.get() == "invitations">
                    <InvitationsSection base_url=base_url_c.clone() token=token_c.clone() />
                </Show>
            </div>
        </div>
    }
}
