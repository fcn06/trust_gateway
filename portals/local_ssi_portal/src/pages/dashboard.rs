//! Dashboard page — WS5.3 overhaul.
//!
//! Fetches real governance stats from the Trust Gateway and shows
//! Quick Actions, recent action feed, and system status.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;

#[component]
pub fn Dashboard(
    username: String,
    token: String,
    base_url: String,
    set_active_section: WriteSignal<String>,
) -> impl IntoView {

    // WS5.3: Governance stats from Trust Gateway
    let (gw_stats, set_gw_stats) = signal(GovStats::default());
    let (recent_actions, set_recent_actions) = signal(Vec::<serde_json::Value>::new());

    let gateway_url: String = {
        let mut gw = if base_url.contains(":3000") {
            base_url.replace(":3000", ":3060")
        } else if base_url.contains(":8080") {
            base_url.replace(":8080", ":3060")
        } else {
            option_env!("TRUST_GATEWAY_URL").unwrap_or("http://localhost:3060").to_string()
        };
        if gw.ends_with("/api") {
            gw.truncate(gw.len() - 4);
        }
        gw
    };

    let gw = gateway_url.clone();
    let tok_for_gw = token.clone();
    Effect::new(move |_| {
        let gw = gw.clone();
        let tok = tok_for_gw.clone();
        spawn_local(async move {
            if let Ok(resp) = reqwasm::http::Request::get(&format!("{}/api/actions?limit=100", gw))
                .header("Authorization", &format!("Bearer {}", tok))
                .send().await
            {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(actions) = data.get("actions").and_then(|a| a.as_array()) {
                        let total = actions.len();
                        let pending = actions.iter().filter(|a| {
                            let s = a.get("status").and_then(|s| s.as_str()).unwrap_or("");
                            s == "pending" || s == "waiting_approval" || s == "waiting_proof"
                        }).count();
                        let executed = actions.iter().filter(|a| {
                            a.get("status").and_then(|s| s.as_str()) == Some("executed")
                        }).count();
                        let denied = actions.iter().filter(|a| {
                            let s = a.get("status").and_then(|s| s.as_str()).unwrap_or("");
                            s == "denied" || s == "failed"
                        }).count();

                        set_gw_stats.set(GovStats { total, pending, executed, denied });
                        // Last 5 actions for the recent feed
                        set_recent_actions.set(actions.iter().take(5).cloned().collect());
                    }
                }
            }
        });
    });

    view! {
        <div class="space-y-6">
            // Welcome header
            <div class="bg-gradient-to-br from-slate-800 to-slate-900 p-6 rounded-2xl border border-slate-700 shadow-xl relative overflow-hidden">
                <div class="absolute -top-16 -right-16 w-32 h-32 bg-blue-500/10 rounded-full blur-3xl"></div>
                <div class="relative z-10">
                    <h2 class="text-2xl font-bold text-white">"Welcome, " {move || username.clone()}</h2>
                    <p class="text-slate-400 text-sm mt-1">"Your command center at a glance"</p>
                </div>
            </div>

            // WS5.3: Governance Stats (real data)
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-blue-500/10 border border-blue-500/20 p-5 rounded-2xl">
                    <div class="flex items-center justify-between mb-3">
                        <span class="text-sm text-blue-400/80 font-medium">"Actions Today"</span>
                        <span class="text-xl">"📊"</span>
                    </div>
                    <div class="text-3xl font-bold text-blue-400">{move || gw_stats.get().total.to_string()}</div>
                </div>
                <div class="bg-amber-500/10 border border-amber-500/20 p-5 rounded-2xl">
                    <div class="flex items-center justify-between mb-3">
                        <span class="text-sm text-amber-400/80 font-medium">"Pending Approvals"</span>
                        <span class="text-xl">"⏳"</span>
                    </div>
                    <div class="text-3xl font-bold text-amber-400">{move || gw_stats.get().pending.to_string()}</div>
                </div>
                <div class="bg-emerald-500/10 border border-emerald-500/20 p-5 rounded-2xl">
                    <div class="flex items-center justify-between mb-3">
                        <span class="text-sm text-emerald-400/80 font-medium">"Executed"</span>
                        <span class="text-xl">"✅"</span>
                    </div>
                    <div class="text-3xl font-bold text-emerald-400">{move || gw_stats.get().executed.to_string()}</div>
                </div>
                <div class="bg-red-500/10 border border-red-500/20 p-5 rounded-2xl">
                    <div class="flex items-center justify-between mb-3">
                        <span class="text-sm text-red-400/80 font-medium">"Denied"</span>
                        <span class="text-xl">"🚫"</span>
                    </div>
                    <div class="text-3xl font-bold text-red-400">{move || gw_stats.get().denied.to_string()}</div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                // Left column: Quick Actions + Recent Actions
                <div class="md:col-span-2 space-y-6">
                    // Getting Started / Quick Actions
                    <Show when=move || gw_stats.get().total == 0 && recent_actions.get().is_empty()>
                        <div class="bg-gradient-to-br from-blue-900/30 to-purple-900/20 p-6 rounded-2xl border border-blue-500/20 shadow-xl">
                            <h3 class="text-lg font-bold mb-1 text-white">"Getting Started"</h3>
                            <p class="text-sm text-slate-400 mb-4">"Complete these steps to set up your agent."</p>
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                                <button 
                                    on:click=move |_| set_active_section.set("manage_identities".to_string())
                                    class="bg-slate-800/70 hover:bg-slate-700/70 border border-slate-700/50 p-4 rounded-xl flex items-center gap-3 text-left w-full transition-all group"
                                >
                                    <span class="text-2xl group-hover:scale-110 transition-transform">"1️⃣"</span>
                                    <div>
                                        <p class="text-sm font-bold text-white group-hover:text-blue-400 transition-colors">"Set up profile"</p>
                                        <p class="text-xs text-slate-500">"Create your identity"</p>
                                    </div>
                                </button>
                                <button 
                                    on:click=move |_| set_active_section.set("contact_requests".to_string())
                                    class="bg-slate-800/70 hover:bg-slate-700/70 border border-slate-700/50 p-4 rounded-xl flex items-center gap-3 text-left w-full transition-all group"
                                >
                                    <span class="text-2xl group-hover:scale-110 transition-transform">"2️⃣"</span>
                                    <div>
                                        <p class="text-sm font-bold text-white group-hover:text-blue-400 transition-colors">"Add a contact"</p>
                                        <p class="text-xs text-slate-500">"Connect with someone"</p>
                                    </div>
                                </button>
                                <button 
                                    on:click=move |_| set_active_section.set("unified_inbox".to_string())
                                    class="bg-slate-800/70 hover:bg-slate-700/70 border border-slate-700/50 p-4 rounded-xl flex items-center gap-3 text-left w-full transition-all group"
                                >
                                    <span class="text-2xl group-hover:scale-110 transition-transform">"3️⃣"</span>
                                    <div>
                                        <p class="text-sm font-bold text-white group-hover:text-blue-400 transition-colors">"Try your agent"</p>
                                        <p class="text-xs text-slate-500">"Send a message"</p>
                                    </div>
                                </button>
                            </div>
                        </div>
                    </Show>

                    // WS5.3: Recent Actions Feed
                    <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                        <h3 class="text-lg font-bold mb-4 text-white">"Recent Governance Actions"</h3>
                        <Show when=move || recent_actions.get().is_empty()>
                            <div class="text-center py-8 text-slate-500">
                                <span class="text-3xl block mb-2">"📭"</span>
                                <p class="text-sm">"No actions yet. Actions will appear once the agent processes requests."</p>
                            </div>
                        </Show>
                        <div class="space-y-2">
                            {move || recent_actions.get().into_iter().map(|action| {
                                let title = action.get("title").and_then(|t| t.as_str()).unwrap_or("Unknown").to_string();
                                let status = action.get("status").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();
                                let created = action.get("created_at").and_then(|c| c.as_str()).unwrap_or("").to_string();
                                let status_class = match status.as_str() {
                                    "executed" => "bg-emerald-500/20 text-emerald-400",
                                    "denied" | "failed" => "bg-red-500/20 text-red-400",
                                    "waiting_approval" | "pending" => "bg-amber-500/20 text-amber-400",
                                    _ => "bg-slate-500/20 text-slate-400",
                                };
                                let icon = match status.as_str() {
                                    "executed" => "✅",
                                    "denied" | "failed" => "❌",
                                    "waiting_approval" | "pending" => "⏳",
                                    _ => "📝",
                                };
                                view! {
                                    <div class="flex items-center justify-between bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
                                        <div class="flex items-center gap-3 min-w-0">
                                            <span class="text-lg">{icon}</span>
                                            <span class="text-sm text-white font-medium truncate">{title}</span>
                                        </div>
                                        <div class="flex items-center gap-3 shrink-0">
                                            <span class=format!("px-2 py-0.5 rounded text-[10px] font-bold uppercase {}", status_class)>
                                                {status}
                                            </span>
                                            <span class="text-[10px] text-slate-500">{created}</span>
                                        </div>
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    </div>

                    </div>

                // Right column
                <div class="space-y-6">
                    <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                        <h3 class="text-lg font-bold mb-4 text-white">"Active Passkey"</h3>
                        <div class="bg-blue-600/10 border border-blue-500/20 p-3 rounded-lg flex items-center gap-3">
                            <div class="w-10 h-10 bg-blue-500/20 rounded-full flex items-center justify-center text-blue-400 text-xl shadow-inner">
                                 "🔑"
                            </div>
                            <div>
                                <p class="text-sm font-bold text-white">"Primary Passkey"</p>
                                <p class="text-[10px] text-slate-500">"Verified with Biometrics"</p>
                            </div>
                        </div>
                    </div>

                    <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                        <details class="group">
                            <summary class="text-lg font-bold text-white cursor-pointer list-none flex items-center justify-between">
                                "Technical Details"
                                <svg class="w-4 h-4 text-slate-500 transform group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                            </summary>
                            <div class="space-y-2 text-xs text-slate-400 mt-3 pt-3 border-t border-slate-700">
                                <div class="flex justify-between">
                                    <span>"Protocol"</span><span class="text-slate-300 font-mono">"Wasm-native"</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>"Identity"</span><span class="text-slate-300 font-mono">"DID:twin"</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>"Messaging"</span><span class="text-slate-300 font-mono">"OpenMLS"</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>"Auth"</span><span class="text-slate-300 font-mono">"WebAuthn"</span>
                                </div>
                            </div>
                        </details>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[derive(Debug, Clone, Default)]
struct GovStats {
    total: usize,
    pending: usize,
    executed: usize,
    denied: usize,
}
