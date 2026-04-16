//! Agent Registry UI
//!
//! Provides a visual interface to view and manage registered agents,
//! check their status, and trigger emergency kill switches.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;

#[component]
pub fn AgentRegistry(
    base_url: String,
    #[allow(unused_variables)] token: String,
) -> impl IntoView {
    let (agents, set_agents) = signal(Vec::<Value>::new());
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(String::new());

    let gateway_url: String = {
        let mut gw = if base_url.contains(":3000") {
            base_url.replace(":3000", ":3060")
        } else if base_url.contains(":8080") {
            base_url.replace(":8080", ":3060")
        } else {
            "http://localhost:3060".to_string()
        };
        if gw.ends_with("/api") {
            gw.truncate(gw.len() - 4);
        }
        gw
    };

    let gw_url = gateway_url.clone();
    
    let load_agents = move || {
        let gw = gw_url.clone();
        spawn_local(async move {
            set_loading.set(true);
            if let Ok(resp) = reqwasm::http::Request::get(&format!("{}/v1/agents", gw))
                .send().await
            {
                if resp.ok() {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(arr) = data.get("agents").and_then(|v| v.as_array()) {
                            set_agents.set(arr.clone());
                            set_error_msg.set(String::new());
                        } else {
                            set_error_msg.set("Unexpected API response format".to_string());
                        }
                    } else {
                        set_error_msg.set("Failed to parse agent data".to_string());
                    }
                } else {
                    set_error_msg.set(format!("Gateway error: {}", resp.status()));
                }
            } else {
                set_error_msg.set("Failed to connect to Trust Gateway".to_string());
            }
            set_loading.set(false);
        });
    };

    let lr = load_agents.clone();
    Effect::new(move |_| lr());

    let gw_tks = gateway_url.clone();
    let load_agents_tks = load_agents.clone();

    view! {
        <div class="space-y-6 max-w-6xl mx-auto">
            // Header
            <div class="flex items-center justify-between bg-slate-900 border border-slate-700/50 p-6 rounded-2xl shadow-xl">
                <div>
                    <h1 class="text-3xl font-bold font-mono text-emerald-400 flex items-center gap-3">
                        <span class="text-3xl">"🤖"</span>
                        "Agent Registry"
                    </h1>
                    <p class="text-sm text-slate-400 mt-1 max-w-xl">
                        "Directory of all identified autonomous agents, swarms, and internal automations operating within your environment."
                    </p>
                </div>
                <button
                    on:click=move |_| load_agents()
                    class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-sm text-white font-medium shadow-sm transition-colors"
                >
                    "Refresh"
                </button>
            </div>

            <Show when=move || !error_msg.get().is_empty()>
                <div class="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-xl text-sm">
                    {move || error_msg.get()}
                </div>
            </Show>

            <div class="space-y-4 animate-in fade-in duration-300">
                <Show when=move || loading.get() && agents.get().is_empty()>
                    <div class="text-center py-12 text-slate-500">
                        <div class="animate-spin w-8 h-8 border-4 border-emerald-500 border-t-transparent rounded-full mx-auto mb-4"></div>
                        "Loading agents..."
                    </div>
                </Show>

                <Show when=move || !loading.get() && agents.get().is_empty()>
                    <div class="bg-slate-800/50 rounded-2xl p-12 text-center border border-slate-700/50 border-dashed">
                        <span class="text-4xl block mb-4">"🤖"</span>
                        <p class="text-slate-300 font-medium">"No agents registered."</p>
                    </div>
                </Show>

                <div class="grid gap-4 md:grid-cols-2">
                    {move || {
                        let gw = gw_tks.clone();
                        let loader = load_agents_tks.clone();
                        
                        agents.get().into_iter().map(move |agent| {
                            let id = agent.get("agent_id").and_then(|i| i.as_str()).unwrap_or("unknown").to_string();
                            let name = agent.get("name").and_then(|i| i.as_str()).unwrap_or("unknown").to_string();
                            let agent_type = agent.get("agent_type").and_then(|t| t.as_str()).unwrap_or("unknown").to_string();
                            let status = agent.get("status").and_then(|s| s.as_str()).unwrap_or("Active").to_string();
                            let kill_switch = agent.get("kill_switch").and_then(|k| k.as_bool()).unwrap_or(false);
                            let profile = agent.get("policy_profile").and_then(|p| p.as_str()).unwrap_or("-").to_string();
                            
                            let kill_btn_class = if kill_switch {
                                "px-3 py-1.5 bg-emerald-900/20 hover:bg-emerald-900/50 text-xs font-bold text-emerald-400 rounded border border-emerald-500/30 transition-colors"
                            } else {
                                "px-3 py-1.5 bg-red-900/20 hover:bg-red-900/50 text-xs font-bold text-red-400 rounded border border-red-500/30 transition-colors"
                            };
                            let kill_btn_text = if kill_switch { "Revive" } else { "Kill Switch" };

                            let status_badge = if kill_switch {
                                "bg-red-500/20 text-red-400 border-red-500/30"
                            } else if status == "Active" {
                                "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                            } else if status == "Paused" {
                                "bg-amber-500/20 text-amber-400 border-amber-500/30"
                            } else {
                                "bg-slate-500/20 text-slate-400 border-slate-500/30"
                            };

                            let display_status = if kill_switch { "KILLED".to_string() } else { status.clone() };
                            let agent_id_capture = id.clone();
                            let gw_inner = gw.clone();
                            let loader_inner = loader.clone();

                        view! {
                            <div class="bg-[#0A0D14] border border-slate-700/50 rounded-xl p-5 flex flex-col hover:border-emerald-500/30 transition-colors relative overflow-hidden shadow-lg">
                                {if kill_switch {
                                    view!{ <div class="absolute inset-0 bg-red-900/5 pointer-events-none"></div> }.into_any()
                                } else {
                                    view!{ <div></div> }.into_any()
                                }}
                                <div class="flex items-start justify-between mb-4 z-10">
                                    <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 bg-slate-800 rounded-full flex items-center justify-center text-xl shadow-inner border border-slate-700">
                                            {match agent_type.as_str() {
                                                "InternalAgent" => "⚙️",
                                                "ExternalSwarm" => "🐝",
                                                "Automation" => "⚡",
                                                _ => "🤖"
                                            }}
                                        </div>
                                        <div>
                                            <h3 class="font-bold text-white text-lg leading-tight">{name}</h3>
                                            <div class="font-mono text-[10px] text-slate-500 mt-1 truncate max-w-[200px]">{id.clone()}</div>
                                        </div>
                                    </div>
                                    <span class=format!("px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border {}", status_badge)>
                                        {display_status}
                                    </span>
                                </div>
                                <div class="space-y-2 mb-4 flex-1 z-10">
                                    <div class="flex justify-between text-xs">
                                        <span class="text-slate-500">"Type:"</span>
                                        <span class="text-slate-300 font-mono font-medium">{agent_type}</span>
                                    </div>
                                    <div class="flex justify-between text-xs">
                                        <span class="text-slate-500">"Profile:"</span>
                                        <span class="text-slate-300 font-mono font-medium">{profile}</span>
                                    </div>
                                </div>
                                <div class="pt-4 border-t border-slate-800/80 flex justify-between items-center z-10">
                                    <div class="text-[10px] uppercase font-bold tracking-wider text-slate-500 flex items-center gap-1.5">
                                        <div class=format!("w-2 h-2 rounded-full {}", if kill_switch { "bg-red-500/50" } else { "bg-emerald-500/50 border border-emerald-500" })></div>
                                        {if kill_switch { "Emergency halted" } else { "Operational" }}
                                    </div>
                                    <button 
                                        on:click=move |_| {
                                            let endpoint = if kill_switch { "revive" } else { "kill" };
                                            let gw2 = gw_inner.clone();
                                            let loader2 = loader_inner.clone();
                                            let aid = agent_id_capture.clone();
                                            spawn_local(async move {
                                                let _ = reqwasm::http::Request::post(&format!("{}/v1/agents/{}/{}", gw2, aid, endpoint))
                                                    .send().await;
                                                loader2();
                                            });
                                        }
                                        class=kill_btn_class
                                    >
                                        {kill_btn_text}
                                    </button>
                                </div>
                            </div>
                        }
                    }).collect_view()
                    }}
                </div>
            </div>
        </div>
    }
}
