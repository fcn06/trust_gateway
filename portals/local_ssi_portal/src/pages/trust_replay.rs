//! Trust Replay — Action timeline replay page.
//!
//! Displays a list of all governed actions with their current status,
//! and a detail view with a vertical timeline showing each governance
//! event that occurred.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

/// Trust Replay page component.
#[component]
pub fn TrustReplay(
    #[prop(into)] base_url: String,
    #[prop(into)] token: String,
) -> impl IntoView {
    let (actions, set_actions) = signal(Vec::<serde_json::Value>::new());
    let (selected_action, set_selected_action) = signal(Option::<serde_json::Value>::None);
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);

    // Compute Trust Gateway URL (port 3060) and remove trailing /api if present
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

    // Fetch actions on mount
    let gw = gateway_url.clone();
    let tok_on_mount = token.clone();
    Effect::new(move |_| {
        let url = gw.clone();
        let tok = tok_on_mount.clone();
        set_loading.set(true);
        spawn_local(async move {
            match reqwasm::http::Request::get(&format!("{}/api/actions?limit=100", url))
                .header("Authorization", &format!("Bearer {}", tok))
                .send()
                .await
            {
                Ok(resp) => {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(arr) = data.get("actions").and_then(|a| a.as_array()) {
                            set_actions.set(arr.clone());
                        }
                        set_error_msg.set(None);
                    } else {
                        set_error_msg.set(Some(format!("Failed to parse response: {}", resp.status())));
                    }
                }
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to fetch actions: {}", e)));
                }
            }
            set_loading.set(false);
        });
    });

    // Store gateway URL and token in signals so on:click handlers can read them
    let (gw_url_sig, _) = signal(gateway_url);
    let (token_sig, _) = signal(token);

    // WS3.2: Filter state
    let (status_filter, set_status_filter) = signal("all".to_string());

    // WS3.2: Compute stats from actions
    let stats = move || {
        let all = actions.get();
        let total = all.len();
        let pending = all.iter().filter(|a| {
            let s = a.get("status").and_then(|s| s.as_str()).unwrap_or("");
            s == "pending" || s == "waiting_approval" || s == "waiting_proof"
        }).count();
        let approved = all.iter().filter(|a| {
            let s = a.get("status").and_then(|s| s.as_str()).unwrap_or("");
            s == "approved" || s == "executed"
        }).count();
        let denied = all.iter().filter(|a| {
            let s = a.get("status").and_then(|s| s.as_str()).unwrap_or("");
            s == "denied" || s == "failed"
        }).count();
        (total, pending, approved, denied)
    };

    // WS3.2: Filtered actions
    let filtered_actions = move || {
        let filter = status_filter.get();
        let all = actions.get();
        if filter == "all" { return all; }
        all.into_iter().filter(|a| {
            let s = a.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string();
            match filter.as_str() {
                "pending" => s == "pending" || s == "waiting_approval" || s == "waiting_proof",
                "approved" => s == "approved" || s == "executed",
                "denied" => s == "denied",
                "failed" => s == "failed",
                _ => true,
            }
        }).collect()
    };

    view! {
        <div class="space-y-6">
            // Header
            <div class="flex items-center justify-between">
                <div>
                    <h2 class="text-2xl font-bold text-white flex items-center gap-3">
                        <span class="text-3xl">"🔄"</span>
                        "Trust Replay"
                    </h2>
                    <p class="text-slate-400 mt-1">"Review the full governance timeline for every action"</p>
                </div>
                <Show when=move || selected_action.get().is_some()>
                    <button
                        on:click=move |_| set_selected_action.set(None)
                        class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm transition-colors"
                    >
                        "← Back to list"
                    </button>
                </Show>
            </div>

            // WS3.2: Summary Stats
            <Show when=move || selected_action.get().is_none()>
                <div class="grid grid-cols-4 gap-3 text-center">
                    <div class="bg-slate-800/60 rounded-lg p-3 border border-slate-700/50">
                        <div class="text-2xl font-bold text-white">{move || stats().0.to_string()}</div>
                        <div class="text-[10px] text-slate-400 uppercase tracking-wider mt-1">"Total"</div>
                    </div>
                    <div class="bg-amber-500/10 rounded-lg p-3 border border-amber-500/20">
                        <div class="text-2xl font-bold text-amber-400">{move || stats().1.to_string()}</div>
                        <div class="text-[10px] text-amber-400/70 uppercase tracking-wider mt-1">"Pending"</div>
                    </div>
                    <div class="bg-green-500/10 rounded-lg p-3 border border-green-500/20">
                        <div class="text-2xl font-bold text-green-400">{move || stats().2.to_string()}</div>
                        <div class="text-[10px] text-green-400/70 uppercase tracking-wider mt-1">"Approved"</div>
                    </div>
                    <div class="bg-red-500/10 rounded-lg p-3 border border-red-500/20">
                        <div class="text-2xl font-bold text-red-400">{move || stats().3.to_string()}</div>
                        <div class="text-[10px] text-red-400/70 uppercase tracking-wider mt-1">"Denied"</div>
                    </div>
                </div>
            </Show>

            // WS3.2: Filter Tabs
            <Show when=move || selected_action.get().is_none()>
                <div class="flex gap-2">
                    {["all", "pending", "approved", "denied", "failed"].into_iter().map(|tab| {
                        let tab_str = tab.to_string();
                        let label = match tab {
                            "all" => "All",
                            "pending" => "⏳ Pending",
                            "approved" => "✅ Approved",
                            "denied" => "❌ Denied",
                            "failed" => "💥 Failed",
                            _ => tab,
                        };
                        view! {
                            <button
                                on:click=move |_| set_status_filter.set(tab_str.clone())
                                class=move || format!(
                                    "px-3 py-1.5 rounded-lg text-xs font-bold transition-all {}",
                                    if status_filter.get() == tab {
                                        "bg-blue-600 text-white shadow-lg"
                                    } else {
                                        "bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 border border-slate-700"
                                    }
                                )
                            >
                                {label}
                            </button>
                        }
                    }).collect_view()}
                </div>
            </Show>

            // Error display
            {move || error_msg.get().map(|e| view! {
                <div class="bg-red-900/30 border border-red-500/30 rounded-lg p-4 text-red-300 text-sm">
                    {e}
                </div>
            })}

            // Loading
            <Show when=move || loading.get()>
                <div class="flex items-center justify-center py-12">
                    <div class="animate-spin w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full"></div>
                </div>
            </Show>

            // Detail view
            <Show when=move || selected_action.get().is_some()>
                {move || selected_action.get().map(|action| {
                    let title = action.get("summary")
                        .and_then(|s| s.get("title"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("Unknown action")
                        .to_string();
                    let status = action.get("summary")
                        .and_then(|s| s.get("status"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let action_name = action.get("summary")
                        .and_then(|s| s.get("action_name"))
                        .and_then(|a| a.as_str())
                        .unwrap_or("")
                        .to_string();
                    let timeline = action.get("timeline")
                        .and_then(|t| t.as_array())
                        .cloned()
                        .unwrap_or_default();

                    view! {
                        <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                            <div class="flex items-center gap-3 mb-6">
                                <div class="w-12 h-12 rounded-lg bg-blue-900/30 border border-blue-500/20 flex items-center justify-center">
                                    <span class="text-2xl">"🔄"</span>
                                </div>
                                <div>
                                    <h3 class="text-xl font-bold text-white">{title}</h3>
                                    <div class="flex items-center gap-2 mt-1">
                                        <span class=format!(
                                            "px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase {}",
                                            match status.as_str() {
                                                "pending" | "waiting_approval" | "waiting_proof" => "bg-amber-500/20 text-amber-400 border border-amber-500/30",
                                                "approved" => "bg-green-500/20 text-green-400 border border-green-500/30",
                                                "denied" => "bg-red-500/20 text-red-400 border border-red-500/30",
                                                "executed" => "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
                                                "failed" => "bg-red-500/20 text-red-400 border border-red-500/30",
                                                _ => "bg-slate-500/20 text-slate-400 border border-slate-500/30",
                                            }
                                        )>
                                            {status.clone()}
                                        </span>
                                        <span class="text-xs text-slate-500">{action_name}</span>
                                    </div>
                                </div>
                            </div>

                            // Vertical timeline
                            <div class="relative ml-6 pl-6 border-l-2 border-slate-600 space-y-4">
                                {timeline.into_iter().rev().map(|event| {
                                    let label = event.get("label").and_then(|l| l.as_str()).unwrap_or("Event").to_string();
                                    let at = event.get("at").and_then(|a| a.as_str()).unwrap_or("").to_string();
                                    let component = event.get("component").and_then(|c| c.as_str()).unwrap_or("").to_string();
                                    let event_type = event.get("event_type").and_then(|e| e.as_str()).unwrap_or("").to_string();
                                    let details = event.get("details").cloned().unwrap_or(serde_json::json!({}));
                                    let details_pretty = serde_json::to_string_pretty(&details).unwrap_or_default();
                                    let has_details = details != serde_json::json!({});

                                    // WS3.3: Fixed — use underscore format matching stored event types
                                    let (dot_color, event_icon) = match event_type.as_str() {
                                        "action_proposed" => ("bg-blue-500", "📤"),
                                        "policy_evaluated" => ("bg-indigo-500", "⚖️"),
                                        "approval_requested" | "proof_requested" => ("bg-amber-500", "⏳"),
                                        "approval_approved" | "proof_verified" => ("bg-green-500", "✅"),
                                        "approval_denied" => ("bg-red-500", "❌"),
                                        "grant_issued" => ("bg-emerald-500", "🔑"),
                                        "connector_invoked" => ("bg-indigo-400", "⚡"),
                                        "action_succeeded" => ("bg-emerald-400", "🎉"),
                                        "action_failed" => ("bg-red-400", "💥"),
                                        "action_retried" => ("bg-amber-400", "🔄"),
                                        "proof_presented" => ("bg-cyan-500", "🛡️"),
                                        _ => ("bg-slate-500", "📝"),
                                    };

                                    view! {
                                        <div class="relative">
                                            <div class=format!("absolute -left-[35px] top-1 w-6 h-6 rounded-full {} ring-4 ring-slate-800 flex items-center justify-center text-xs shadow-lg", dot_color)>
                                                {event_icon}
                                            </div>
                                            <div class="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
                                                <div class="flex items-center justify-between">
                                                    <span class="font-medium text-white text-sm">{label}</span>
                                                    <span class="text-[10px] text-slate-500">{at}</span>
                                                </div>
                                                <div class="flex items-center gap-2 mt-1">
                                                    <span class="text-[10px] text-slate-500">{component}</span>
                                                </div>
                                                {if has_details { Some(view! {
                                                    <details class="mt-2">
                                                        <summary class="text-[10px] text-slate-500 cursor-pointer hover:text-slate-300">"▸ Details"</summary>
                                                        <pre class="text-[10px] text-slate-400 mt-1 whitespace-pre-wrap break-all">
                                                            {details_pretty}
                                                        </pre>
                                                    </details>
                                                })} else { None }}
                                            </div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    }
                })}
            </Show>

            // List view (WS3.2: uses filtered_actions)
            <Show when=move || selected_action.get().is_none() && !loading.get()>
                <Show when=move || actions.get().is_empty()>
                    <div class="text-center py-12">
                        <span class="text-5xl">"📭"</span>
                        <p class="text-slate-400 mt-4">"No actions recorded yet"</p>
                        <p class="text-slate-500 text-sm mt-1">"Actions will appear here once the Trust Gateway processes them"</p>
                    </div>
                </Show>
                <Show when=move || !actions.get().is_empty()>
                    <div class="space-y-3">
                        {move || filtered_actions().into_iter().map(|action| {
                            let action_id = action.get("action_id").and_then(|a| a.as_str()).unwrap_or("").to_string();
                            let title = action.get("title").and_then(|t| t.as_str()).unwrap_or("Unknown").to_string();
                            let status = action.get("status").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();
                            let status_icon = status.clone();
                            let status_badge = status.clone();
                            let source = action.get("source_type").and_then(|s| s.as_str()).unwrap_or("").to_string();
                            let event_count = action.get("event_count").and_then(|c| c.as_u64()).unwrap_or(0);
                            let created = action.get("created_at").and_then(|c| c.as_str()).unwrap_or("").to_string();
                            let aid = action_id.clone();

                            view! {
                                <div
                                    class="bg-slate-800 rounded-xl p-4 border border-slate-700 hover:border-blue-500/30 transition-all cursor-pointer group"
                                    on:click=move |_| {
                                        let url = gw_url_sig.get();
                                        let tok = token_sig.get();
                                        let id = aid.clone();
                                        spawn_local(async move {
                                            match reqwasm::http::Request::get(&format!("{}/api/actions/{}", url, id))
                                                .header("Authorization", &format!("Bearer {}", tok))
                                                .send()
                                                .await
                                            {
                                                Ok(resp) => {
                                                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                                                        set_selected_action.set(Some(data));
                                                    }
                                                }
                                                Err(e) => {
                                                    log::warn!("Failed to fetch action detail: {}", e);
                                                }
                                            }
                                        });
                                    }
                                >
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <div class="w-8 h-8 rounded-lg bg-slate-700/50 flex items-center justify-center">
                                                <span class="text-sm">{
                                                    match status_icon.as_str() {
                                                        "executed" => "✅",
                                                        "denied" | "failed" => "❌",
                                                        "approved" => "✅",
                                                        _ => "⏳",
                                                    }
                                                }</span>
                                            </div>
                                            <div>
                                                <h4 class="text-sm font-bold text-white group-hover:text-blue-400 transition-colors">{title}</h4>
                                                <div class="flex items-center gap-2 mt-0.5">
                                                    <span class=format!(
                                                        "px-2 py-0.5 rounded text-[10px] font-bold uppercase {}",
                                                        match status_badge.as_str() {
                                                            "pending" | "waiting_approval" | "waiting_proof" => "bg-amber-500/20 text-amber-400",
                                                            "approved" | "executed" => "bg-green-500/20 text-green-400",
                                                            "denied" | "failed" => "bg-red-500/20 text-red-400",
                                                            _ => "bg-slate-500/20 text-slate-400",
                                                        }
                                                    )>
                                                        {status}
                                                    </span>
                                                    {if !source.is_empty() { Some(view! {
                                                        <span class="text-[10px] text-slate-500">{"📡 "}{source}</span>
                                                    })} else { None }}
                                                    <span class="text-[10px] text-slate-500">{format!("{} events", event_count)}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="text-xs text-slate-500">{created}</div>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                </Show>
            </Show>
        </div>
    }
}
