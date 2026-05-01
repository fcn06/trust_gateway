//! Tenant Settings page — configuration, billing, and team management.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::{EnrichedIdentity, RegistrationCookie};

#[component]
pub fn Settings(
    base_url: String,
    token: String,
    registration_cookie: ReadSignal<Option<RegistrationCookie>>,
) -> impl IntoView {
    let (identities, set_identities) = signal(Vec::<EnrichedIdentity>::new());
    let (loading, set_loading) = signal(true);
    let (updating, set_updating) = signal(false);
    let (invite_code, set_invite_code) = signal(Option::<String>::None);
    let (generating_invite, set_generating_invite) = signal(false);

    let base_clone = base_url.clone();
    let token_clone = token.clone();
    Effect::new(move |_| {
        let base = base_clone.clone();
        let tok = token_clone.clone();
        spawn_local(async move {
            set_loading.set(true);
            if let Ok(list) = api::list_identities(&base, tok).await {
                set_identities.set(list);
            }
            set_loading.set(false);
        });
    });

    let main_did = move || identities.get().first().cloned();

    /// Gate: Only allow specific tenants to enable the AI Receptionist/Agent features.
    let is_agent_allowed = move || {
        registration_cookie.get().map(|c| c.is_agent_allowed).unwrap_or(false)
    };

    let toggle_institutional = Callback::new({
        let base_url = base_url.clone();
        let token = token.clone();
        move |_| {
            if let Some(id) = main_did() {
                let base = base_url.clone();
                let tok = token.clone();
                let new_val = !id.is_institutional;
                let did = id.did.clone();
                let alias = id.alias.clone();
                
                spawn_local(async move {
                    set_updating.set(true);
                    if let Ok(_) = api::enrich_identity(&base, did.clone(), alias.clone(), new_val, tok.clone()).await {
                        // Refresh list
                        if let Ok(list) = api::list_identities(&base, tok).await {
                            set_identities.set(list);
                        }
                    }
                    set_updating.set(false);
                });
            }
        }
    });

    let generate_invite = {
        let base_url = base_url.clone();
        let token = token.clone();
        move |_| {
            let base = base_url.clone();
            let tok = token.clone();
            spawn_local(async move {
                set_generating_invite.set(true);
                let url = format!("{}/tenant/invite", base);
                match reqwasm::http::Request::post(&url)
                    .credentials(reqwasm::http::RequestCredentials::Include)
                    .header("Authorization", &format!("Bearer {}", tok))
                    .send()
                    .await
                {
                    Ok(resp) if resp.ok() => {
                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                            if let Some(code) = data.get("code").and_then(|c| c.as_str()) {
                                set_invite_code.set(Some(code.to_string()));
                            }
                        }
                    }
                    _ => log::error!("Failed to generate invite"),
                }
                set_generating_invite.set(false);
            });
        }
    };

    let (telegram_code, set_telegram_code) = signal(Option::<String>::None);
    let (generating_telegram, set_generating_telegram) = signal(false);

    let generate_telegram_link = {
        let base_url = base_url.clone();
        let token = token.clone();
        move |_| {
            let base = base_url.clone();
            let tok = token.clone();
            spawn_local(async move {
                set_generating_telegram.set(true);
                let url = format!("{}/link-remote", base);
                match reqwasm::http::Request::post(&url)
                    .credentials(reqwasm::http::RequestCredentials::Include)
                    .header("Authorization", &format!("Bearer {}", tok))
                    .send()
                    .await
                {
                    Ok(resp) if resp.ok() => {
                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                            if let Some(code) = data.get("code").and_then(|c| c.as_str()) {
                                set_telegram_code.set(Some(code.to_string()));
                            }
                        }
                    }
                    _ => log::error!("Failed to generate telegram link code"),
                }
                set_generating_telegram.set(false);
            });
        }
    };

    view! {
        <div class="space-y-8">
            <h1 class="text-2xl font-bold bg-gradient-to-r from-gray-300 to-gray-100 bg-clip-text text-transparent">
                "⚙️ Settings"
            </h1>

            // Tenant Info
            <section class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-white mb-4">"🏢 Organization"</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="text-xs text-gray-400 block mb-1">"Current Tier"</label>
                        <div class="bg-slate-900 p-3 rounded-lg border border-slate-600">
                            <span class="text-sm font-medium text-amber-400">"Professional"</span>
                        </div>
                    </div>
                </div>
                
                <details class="mt-4 pt-4 border-t border-slate-700/50">
                    <summary class="text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">"▸ Advanced Settings"</summary>
                    <div class="mt-3">
                        <label class="text-xs text-gray-400 block mb-1">"Tenant ID"</label>
                        <div class="bg-slate-900 text-gray-500 font-mono text-xs p-2 rounded border border-slate-700 break-all w-full max-w-md">
                            {move || registration_cookie.get().map(|c| c.tenant_id.unwrap_or(c.aid)).unwrap_or_else(|| "Not available".to_string())}
                        </div>
                    </div>
                </details>
            </section>

            // Team Management
            <section class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-white mb-4">"👥 Team Management"</h2>
                <div class="flex flex-col md:flex-row items-start md:items-center justify-between p-4 bg-slate-900 rounded-lg border border-slate-600">
                    <div class="mb-4 md:mb-0">
                        <p class="text-sm font-medium text-white">"Invite Team Members"</p>
                        <p class="text-xs text-gray-400 max-w-sm hover:text-gray-300">"Generate a temporary 6-character code to allow staff to join this workspace during sign-up."</p>
                    </div>
                    <div class="flex items-center gap-4">
                        <Show when=move || invite_code.get().is_some()>
                            <div class="bg-slate-950 border border-amber-500/50 px-4 py-2 rounded-lg text-center">
                                <p class="text-xs text-amber-500/80 mb-1 leading-none uppercase tracking-wider">"Invite Code"</p>
                                <p class="text-lg font-mono font-bold text-white tracking-widest">{move || invite_code.get().unwrap_or_default()}</p>
                            </div>
                        </Show>
                        <button
                            on:click=generate_invite
                            disabled=move || generating_invite.get()
                            class="bg-blue-600 hover:bg-blue-500 test-sm text-white font-medium py-2 px-4 rounded-lg transition-all disabled:opacity-50 shadow-lg shadow-blue-500/20 whitespace-nowrap"
                        >
                            {move || if generating_invite.get() { "Generating..." } else { "Generate Code" }}
                        </button>
                    </div>
                </div>
            </section>

            // Institutional Settings (Agent Toggle) - Restricted to specific tenants
            <Show when=is_agent_allowed>
                <section class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                    <h2 class="text-lg font-semibold text-white mb-4">"🤖 Public AI Receptionist"</h2>
                    <div class="flex items-center justify-between p-4 bg-slate-900 rounded-lg border border-slate-600">
                        <div>
                            <p class="text-sm font-medium text-white">"Enable Auto-Reply"</p>
                            <p class="text-xs text-gray-400">"Automatically respond to messages via AI and bypass ACLs."</p>
                        </div>
                        {move || {
                            if loading.get() || updating.get() {
                                view! { <span class="text-gray-500 italic text-sm">"Loading..."</span> }.into_any()
                            } else if let Some(id) = main_did() {
                                view! {
                                    <button 
                                        on:click=move |e| toggle_institutional.run(e)
                                        class=format!("relative inline-flex h-6 w-11 items-center rounded-full transition-colors {}", if id.is_institutional { "bg-blue-600" } else { "bg-slate-600" })
                                    >
                                        <span class=format!("inline-block h-4 w-4 transform rounded-full bg-white transition-transform {}", if id.is_institutional { "translate-x-6" } else { "translate-x-1" })/>
                                    </button>
                                }.into_any()
                            } else {
                                view! { <span class="text-red-400 text-sm">"No primary identity found"</span> }.into_any()
                            }
                        }}
                    </div>
                </section>
            </Show>

            // LLM Configuration
            <section class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-white mb-4">"🧠 AI Model Configuration"</h2>
                <div class="space-y-4">
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-600">
                        <div>
                            <p class="text-sm font-medium text-white">"Default Model"</p>
                            <p class="text-xs text-gray-400">"Used for standard queries"</p>
                        </div>
                        <span class="text-sm font-mono text-blue-400">"gpt-4o-mini"</span>
                    </div>
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-600">
                        <div>
                            <p class="text-sm font-medium text-white">"Escalation Model"</p>
                            <p class="text-xs text-gray-400">"Used for approved high-stakes operations"</p>
                        </div>
                        <span class="text-sm font-mono text-purple-400">"gpt-4o"</span>
                    </div>
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-600">
                        <div>
                            <p class="text-sm font-medium text-white">"Monthly Token Budget"</p>
                            <p class="text-xs text-gray-400">"Maximum tokens per billing period"</p>
                        </div>
                        <span class="text-sm font-mono text-green-400">"5,000,000"</span>
                    </div>
                </div>
            </section>

            // Usage Metrics
            <section class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-white mb-4">"📊 Usage This Month"</h2>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="bg-gradient-to-br from-blue-900/50 to-blue-800/30 p-4 rounded-xl border border-blue-700/30 text-center">
                        <p class="text-2xl font-bold text-blue-400">"0"</p>
                        <p class="text-xs text-gray-400 mt-1">"LLM Calls"</p>
                    </div>
                    <div class="bg-gradient-to-br from-green-900/50 to-green-800/30 p-4 rounded-xl border border-green-700/30 text-center">
                        <p class="text-2xl font-bold text-green-400">"0"</p>
                        <p class="text-xs text-gray-400 mt-1">"Tool Executions"</p>
                    </div>
                    <div class="bg-gradient-to-br from-amber-900/50 to-amber-800/30 p-4 rounded-xl border border-amber-700/30 text-center">
                        <p class="text-2xl font-bold text-amber-400">"0"</p>
                        <p class="text-xs text-gray-400 mt-1">"Escalations"</p>
                    </div>
                    <div class="bg-gradient-to-br from-purple-900/50 to-purple-800/30 p-4 rounded-xl border border-purple-700/30 text-center">
                        <p class="text-2xl font-bold text-purple-400">"0"</p>
                        <p class="text-xs text-gray-400 mt-1">"Messages"</p>
                    </div>
                </div>
            </section>

            // Channel Configuration
            <section class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-white mb-4">"📡 Channel Configuration"</h2>
                <div class="space-y-3">
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-600">
                        <div class="flex items-center gap-3">
                            <span class="text-xl">"🔐"</span>
                            <div>
                                <p class="text-sm font-medium text-white">"DIDComm"</p>
                                <p class="text-xs text-gray-400">"Always enabled (core)"</p>
                            </div>
                        </div>
                        <span class="text-xs bg-green-500/20 text-green-300 px-2 py-1 rounded-full">"Active"</span>
                    </div>
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-600">
                        <div class="flex items-center gap-3">
                            <span class="text-xl">"📱"</span>
                            <div>
                                <p class="text-sm font-medium text-white">"SMS (Twilio)"</p>
                                <p class="text-xs text-gray-400">"Configure phone number mapping"</p>
                            </div>
                        </div>
                        <span class="text-xs bg-gray-500/20 text-gray-400 px-2 py-1 rounded-full">"Not configured"</span>
                    </div>
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-600 gap-3 sm:gap-0">
                        <div class="flex items-center gap-3">
                            <span class="text-xl">"✈️"</span>
                            <div>
                                <p class="text-sm font-medium text-white">"Telegram Bot"</p>
                                <p class="text-xs text-gray-400">"Receive mobile approvals"</p>
                            </div>
                        </div>
                        <div class="flex items-center gap-3">
                            <Show when=move || telegram_code.get().is_some()>
                                <div class="bg-slate-950 border border-blue-500/50 px-3 py-1 rounded text-center">
                                    <p class="text-[9px] text-blue-400/80 mb-0.5 leading-none uppercase tracking-wider">"Send to Bot"</p>
                                    <p class="text-xs font-mono font-bold text-white">{format!("/start {}", telegram_code.get().unwrap_or_default())}</p>
                                </div>
                            </Show>
                            <button
                                on:click=generate_telegram_link
                                disabled=move || generating_telegram.get()
                                class="bg-slate-700 hover:bg-slate-600 text-xs text-white font-medium py-1.5 px-3 rounded transition-colors disabled:opacity-50 border border-slate-600"
                            >
                                {move || if generating_telegram.get() { "Generating..." } else { "Link Device" }}
                            </button>
                        </div>
                    </div>
                </div>
            </section>

            // Danger Zone
            <section class="bg-red-950/30 rounded-xl p-6 border border-red-800/50">
                <h2 class="text-lg font-semibold text-red-400 mb-4">"⚠️ Danger Zone"</h2>
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-white">"Delete Organization"</p>
                        <p class="text-xs text-gray-400">"This will permanently delete all data"</p>
                    </div>
                    <button class="bg-red-600/20 text-red-400 px-4 py-2 rounded-lg hover:bg-red-600/40 transition-colors text-sm font-medium border border-red-600/30">
                        "Delete"
                    </button>
                </div>
            </section>
        </div>
    }
}
