//! Policy Builder UI — WS4.2
//!
//! Provides a visual interface to manage Trust Gateway governance
//! policies, allowing users to view rules, add tiered rules, and run simulations
//! instead of manually editing TOML files.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;

#[component]
pub fn PolicyBuilder(
    base_url: String,
    token: String,
) -> impl IntoView {
    let (rules, set_rules) = signal(Vec::<Value>::new());
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(String::new());
    let (active_tab, set_active_tab) = signal("rules".to_string());

    // Gateway API proxy setup
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
    
    // Load rules
    let load_rules = move || {
        let gw = gw_url.clone();
        spawn_local(async move {
            set_loading.set(true);
            if let Ok(resp) = reqwasm::http::Request::get(&format!("{}/api/policy/rules", gw))
                .send().await
            {
                if let Ok(data) = resp.json::<Value>().await {
                    if let Some(r) = data.get("rules").and_then(|v| v.as_array()) {
                        set_rules.set(r.clone());
                    }
                } else {
                    set_error_msg.set("Failed to parse policy rules".to_string());
                }
            } else {
                set_error_msg.set("Failed to connect to Trust Gateway".to_string());
            }
            set_loading.set(false);
        });
    };

    let lr = load_rules.clone();
    Effect::new(move |_| lr());

    view! {
        <div class="space-y-6 max-w-6xl mx-auto">
            // Header
            <div class="flex items-center justify-between bg-slate-900 border border-slate-700/50 p-6 rounded-2xl shadow-xl">
                <div>
                    <h1 class="text-3xl font-bold font-mono text-purple-400 flex items-center gap-3">
                        <span class="text-3xl">"📜"</span>
                        "Policy Builder"
                    </h1>
                    <p class="text-sm text-slate-400 mt-1 max-w-xl">
                        "Manage fine-grained governance rules for AI agent actions. "
                        "Define thresholds, require human approval, or trigger step-up verification."
                    </p>
                </div>
                <button
                    on:click=move |_| load_rules()
                    class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-sm text-white font-medium shadow-sm transition-colors"
                >
                    "Refresh Rules"
                </button>
            </div>

            // Tabs
            <div class="flex gap-2 border-b border-slate-700/50 pb-2">
                <button
                    on:click=move |_| set_active_tab.set("rules".to_string())
                    class=move || format!(
                        "px-4 py-2 rounded-t-lg text-sm font-bold transition-all {}",
                        if active_tab.get() == "rules" { "bg-purple-600 text-white shadow-[0_-4px_10px_rgba(147,51,234,0.3)]" } else { "text-slate-400 hover:text-white" }
                    )
                >
                    "Active Rules"
                </button>
                <button
                    on:click=move |_| set_active_tab.set("simulator".to_string())
                    class=move || format!(
                        "px-4 py-2 rounded-t-lg text-sm font-bold transition-all {}",
                        if active_tab.get() == "simulator" { "bg-purple-600 text-white shadow-[0_-4px_10px_rgba(147,51,234,0.3)]" } else { "text-slate-400 hover:text-white" }
                    )
                >
                    "Simulation Engine"
                </button>
            </div>

            <Show when=move || !error_msg.get().is_empty()>
                <div class="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-xl text-sm">
                    {move || error_msg.get()}
                </div>
            </Show>

            // Active Rules Tab
            <Show when=move || active_tab.get() == "rules">
                <div class="space-y-4 animate-in fade-in duration-300">
                    <Show when=move || loading.get() && rules.get().is_empty()>
                        <div class="text-center py-12 text-slate-500">
                            <div class="animate-spin w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4"></div>
                            "Loading policy rules..."
                        </div>
                    </Show>

                    <Show when=move || !loading.get() && rules.get().is_empty()>
                        <div class="bg-slate-800/50 rounded-2xl p-12 text-center border border-slate-700/50 border-dashed">
                            <span class="text-4xl block mb-4">"📜"</span>
                            <p class="text-slate-300 font-medium">"No custom rules found."</p>
                            <p class="text-sm text-slate-500 max-w-md mx-auto mt-2">
                                "The gateway is currently running on implicit default rules (fail-closed). Add rules to permit agent actions."
                            </p>
                        </div>
                    </Show>

                    <div class="grid gap-3">
                        {move || rules.get().into_iter().map(|rule| {
                            let id = rule.get("id").and_then(|i| i.as_str()).unwrap_or("unknown").to_string();
                            let priority = rule.get("priority").and_then(|p| p.as_u64()).unwrap_or(50);
                            let effect = rule.get("effect").and_then(|e| e.as_str()).unwrap_or("unknown").to_string();
                            let reason = rule.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string();
                            let tier = rule.get("tier").and_then(|r| r.as_str());
                            
                            // Effect Badge formatting
                            let effect_badge = match effect.as_str() {
                                "allow" => "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                                "deny" => "bg-red-500/20 text-red-400 border-red-500/30",
                                "require_approval" => "bg-blue-500/20 text-blue-400 border-blue-500/30",
                                "require_proof" => "bg-purple-500/20 text-purple-400 border-purple-500/30",
                                _ => "bg-slate-500/20 text-slate-400 border-slate-500/30",
                            };

                            let display_effect = match effect.as_str() {
                                "allow" => "Allow".to_string(),
                                "deny" => "Deny".to_string(),
                                "require_approval" => "Require Approval".to_string(),
                                "require_proof" => "Require Proof".to_string(),
                                other => other.to_string(),
                            };

                            let action_name = rule.get("action_names").and_then(|a| a.as_array()).and_then(|arr| arr.get(0)).and_then(|v| v.as_str()).map(|s| s.to_string());
                            let category_name = rule.get("categories").and_then(|a| a.as_array()).and_then(|arr| arr.get(0)).and_then(|v| v.as_str()).map(|s| s.to_string());
                            let min_amount = rule.get("min_amount").and_then(|a| a.as_str()).map(|s| s.to_string());

                            view! {
                                <div class="bg-[#0A0D14] border border-slate-700/50 rounded-xl p-4 flex flex-col md:flex-row gap-4 items-start md:items-center hover:border-purple-500/30 transition-colors">
                                    <div class="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center font-mono text-xl text-slate-400 font-bold border border-slate-700 shrink-0">
                                        {priority}
                                    </div>
                                    
                                    <div class="flex-1 min-w-0 space-y-2">
                                        <div class="flex items-center gap-3">
                                            <span class="font-mono text-sm text-white font-bold">{id}</span>
                                            <span class=format!("px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border {}", effect_badge)>
                                                {display_effect}
                                                {tier.map(|t| format!(" ({})", t.replace("tier1_", "").replace("tier3_", "")))}
                                            </span>
                                        </div>
                                        
                                        // Matchers overview
                                        <div class="flex flex-wrap gap-2 text-[10px] font-mono">
                                            {action_name.map(|n| view! { <span class="bg-cyan-900/30 text-cyan-400 px-2 py-0.5 rounded">"Action: " {n}</span> })}
                                            {category_name.map(|c| view! { <span class="bg-emerald-900/30 text-emerald-400 px-2 py-0.5 rounded">"Category: " {c}</span> })}
                                            {min_amount.map(|a| view! { <span class="bg-amber-900/30 text-amber-400 px-2 py-0.5 rounded">"> " {a}</span> })}
                                        </div>
                                        
                                        <div class="text-xs text-slate-500 italic mt-1">
                                            {if !reason.is_empty() { format!("\"{}\"", reason) } else { "".to_string() }}
                                        </div>
                                    </div>
                                    
                                    <div class="shrink-0 flex gap-2">
                                        <button class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300 rounded border border-slate-600 transition-colors">
                                            "Edit"
                                        </button>
                                        <button class="px-3 py-1.5 bg-red-900/20 hover:bg-red-900/50 text-xs font-bold text-red-400 rounded border border-red-500/20 transition-colors">
                                            "Delete"
                                        </button>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                </div>
            </Show>

            // Simulation Engine Tab (dry-run logic goes here for WS4)
            <Show when=move || active_tab.get() == "simulator">
                <div class="space-y-6 animate-in fade-in duration-300">
                    <div class="bg-[#0A0D14] p-6 rounded-2xl border border-slate-700/50">
                        <h3 class="text-lg font-bold text-white mb-2 flex items-center gap-2">
                            <span class="text-purple-400">"🧪"</span> "Simulation Engine"
                        </h3>
                        <p class="text-sm text-slate-400 mb-6">
                            "Test hypothetical tool calls against your live policy rules to see how the Gateway would route them."
                        </p>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl">
                            <div>
                                <label class="block text-xs font-bold text-slate-400 mb-1 uppercase tracking-wider">"Task Action Name"</label>
                                <input type="text" placeholder="e.g. shopify.order.refund" 
                                    class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" value="shopify.order.refund" />
                            </div>
                            <div>
                                <label class="block text-xs font-bold text-slate-400 mb-1 uppercase tracking-wider">"Argument Amount"</label>
                                <input type="text" placeholder="e.g. 500.00" 
                                    class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" value="500.00" />
                            </div>
                            <div class="md:col-span-2">
                                <button class="w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-3 rounded-lg shadow-lg shadow-purple-600/20 transition-all active:scale-[0.98]">
                                    "Run Simulation"
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </Show>
        </div>
    }
}
