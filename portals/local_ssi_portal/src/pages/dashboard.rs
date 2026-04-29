//! Dashboard page — WS5.3 overhaul.
//!
//! Fetches real governance stats from the Trust Gateway and shows
//! Quick Actions, recent action feed, and system status.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;

#[component]
pub fn Dashboard(username: String, token: String, base_url: String) -> impl IntoView {
    let (bridge_code, set_bridge_code) = signal(Option::<String>::None);
    let (is_loading, set_is_loading) = signal(false);

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
    Effect::new(move |_| {
        let gw = gw.clone();
        spawn_local(async move {
            if let Ok(resp) = reqwasm::http::Request::get(&format!("{}/api/actions?limit=100", gw))
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
                    <p class="text-slate-400 text-sm mt-1">"Your sovereign control plane at a glance"</p>
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
                    // WS5.3: Quick Actions
                    <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                        <h3 class="text-lg font-bold mb-4 text-white">"Quick Actions"</h3>
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <a href="#approvals" class="bg-amber-500/10 border border-amber-500/20 p-4 rounded-xl hover:bg-amber-500/20 transition-all group flex items-center gap-3">
                                <span class="text-2xl">"✅"</span>
                                <div>
                                    <p class="text-sm font-bold text-white group-hover:text-amber-400">"Pending Approvals"</p>
                                    <p class="text-xs text-slate-500">{move || format!("{} waiting", gw_stats.get().pending)}</p>
                                </div>
                            </a>
                            <a href="#trust-replay" class="bg-blue-500/10 border border-blue-500/20 p-4 rounded-xl hover:bg-blue-500/20 transition-all group flex items-center gap-3">
                                <span class="text-2xl">"🔄"</span>
                                <div>
                                    <p class="text-sm font-bold text-white group-hover:text-blue-400">"Trust Replay"</p>
                                    <p class="text-xs text-slate-500">"Review action timelines"</p>
                                </div>
                            </a>
                            <a href="#activity" class="bg-cyan-500/10 border border-cyan-500/20 p-4 rounded-xl hover:bg-cyan-500/20 transition-all group flex items-center gap-3">
                                <span class="text-2xl">"📊"</span>
                                <div>
                                    <p class="text-sm font-bold text-white group-hover:text-cyan-400">"Activity Feed"</p>
                                    <p class="text-xs text-slate-500">"All system events"</p>
                                </div>
                            </a>
                        </div>
                    </div>

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

                    // Remote Access
                    <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                        <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
                            <h3 class="text-lg font-bold text-white">"Remote Access"</h3>
                            <Show when=move || bridge_code.get().is_none()>
                                <button
                                    on:click={
                                        let token = token.clone();
                                        let base_url = base_url.clone();
                                        move |_| {
                                            set_is_loading.set(true);
                                            let tok = token.clone();
                                            let bu = base_url.clone();
                                            spawn_local(async move {
                                                match api::link_remote(&bu, tok).await {
                                                    Ok(code) => set_bridge_code.set(Some(code)),
                                                    Err(e) => log::error!("Failed to generate bridge code: {}", e),
                                                }
                                                set_is_loading.set(false);
                                            });
                                        }
                                    }
                                    disabled=move || is_loading.get()
                                    class="bg-purple-600 hover:bg-purple-500 px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-lg shadow-purple-600/20 disabled:opacity-50">
                                    {move || if is_loading.get() { "Generating..." } else { "Link Remote Access" }}
                                </button>
                            </Show>
                        </div>

                        <Show
                            when=move || bridge_code.get().is_some()
                            fallback=move || view! {
                                <p class="text-sm text-slate-400">"Generate a bridge code to link your Global Portal account."</p>
                            }
                        >
                            <div class="bg-slate-900 p-6 rounded-xl border border-purple-500/30 flex flex-col items-center gap-4">
                                <span class="text-xs text-purple-400 font-bold uppercase tracking-wider">"Your Bridge Code"</span>
                                <p class="text-5xl font-black text-white tracking-[0.5rem] font-mono">{move || bridge_code.get().unwrap_or_default()}</p>
                                <p class="text-xs text-slate-500 italic">"Enter this code in the Global Portal. Expires in 5 minutes."</p>
                                <button
                                    on:click=move |_| set_bridge_code.set(None)
                                    class="text-xs text-slate-400 hover:text-white transition-colors">
                                    "Clear Code"
                                </button>
                            </div>
                        </Show>
                    </div>
                </div>

                // Right column: System Status
                <div class="space-y-6">
                    <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                        <h3 class="text-lg font-bold mb-4 text-white">"System Status"</h3>
                        <div class="space-y-3">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center gap-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse shadow-[0_0_8px_rgba(74,222,128,0.5)]"></div>
                                    <span class="text-sm text-slate-300">"Trust Gateway"</span>
                                </div>
                                <span class="text-xs text-green-400 font-bold">"ONLINE"</span>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center gap-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse shadow-[0_0_8px_rgba(74,222,128,0.5)]"></div>
                                    <span class="text-sm text-slate-300">"Host Orchestrator"</span>
                                </div>
                                <span class="text-xs text-green-400 font-bold">"ONLINE"</span>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center gap-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse shadow-[0_0_8px_rgba(74,222,128,0.5)]"></div>
                                    <span class="text-sm text-slate-300">"Policy Engine"</span>
                                </div>
                                <span class="text-xs text-green-400 font-bold">"ACTIVE"</span>
                            </div>
                        </div>
                    </div>

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
                        <h3 class="text-lg font-bold mb-2 text-white">"Architecture"</h3>
                        <div class="space-y-2 text-xs text-slate-400">
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
