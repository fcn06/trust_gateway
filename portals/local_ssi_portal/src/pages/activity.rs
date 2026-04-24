//! Activity Feed — unified governance + system activity stream.
//!
//! WS6: Complete overhaul from raw NOC dump to product-grade activity feed.
//! Fetches from two sources: Host audit events + Trust Gateway governance actions.
//! Groups governance actions into lifecycle cards with progress indicators.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde::{Deserialize, Serialize};

// ─── Unified Activity Model (WS6.1) ────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ActivityCategory {
    GovernanceAction,
    Authentication,
    AgentActivity,
    Messaging,
    System,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActivityItem {
    pub id: String,
    pub timestamp: u64,
    pub category: ActivityCategory,
    pub title: String,
    pub subtitle: String,
    pub status: String,
    pub source: String,
    pub icon: &'static str,
    pub risk_level: Option<String>,
    pub action_id: Option<String>,
    pub event_count: Option<u64>,
    pub details: Vec<(String, String)>,
}

// ─── Raw types for Host event deserialization ───────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostEventRaw {
    jti: Option<String>,
    tenant_id: Option<String>,
    user_did: Option<String>,
    ts: Option<u64>,
    timestamp: Option<String>,
    component: Option<String>,
    action: Option<String>,
    detail: Option<serde_json::Value>,
}

// ─── Event Mapping (WS6.2) ─────────────────────────────────

fn map_host_event(raw: &HostEventRaw) -> ActivityItem {
    let action = raw.action.as_deref().unwrap_or("unknown");
    let detail = raw.detail.clone().unwrap_or(serde_json::json!({}));
    let ts = raw.ts.unwrap_or(0);

    let (icon, title, category) = match action {
        "jwt_issued" => ("🔑", "User signed in".to_string(), ActivityCategory::Authentication),
        "webauthn_registered" => ("🛡️", "Passkey registered".to_string(), ActivityCategory::Authentication),
        "vault_unlocked" => ("🔓", "Vault unlocked".to_string(), ActivityCategory::Authentication),
        "request_dispatched" => {
            let prompt = detail.get("prompt").and_then(|p| p.as_str()).unwrap_or("…");
            let short = if prompt.len() > 60 { format!("{}…", &prompt[..60]) } else { prompt.to_string() };
            ("🧠", format!("Agent processing: \"{}\"", short), ActivityCategory::AgentActivity)
        }
        "llm_call" => ("🧠", "AI reasoning".to_string(), ActivityCategory::AgentActivity),
        "tool_executed" => {
            let tool = detail.get("tool_name").and_then(|t| t.as_str()).unwrap_or("unknown");
            ("⚡", format!("Tool called: {}", tool), ActivityCategory::AgentActivity)
        }
        "mls_message_sent" => ("📤", "Secure message sent".to_string(), ActivityCategory::Messaging),
        "mls_message_received" => ("📥", "Secure message received".to_string(), ActivityCategory::Messaging),
        "contact_request_sent" => ("🤝", "Contact request sent".to_string(), ActivityCategory::Messaging),
        "oauth_linked" => {
            let provider = detail.get("provider").and_then(|p| p.as_str()).unwrap_or("account");
            ("🔗", format!("Account linked: {}", provider), ActivityCategory::System)
        }
        _ => ("📝", action.replace('_', " "), ActivityCategory::System),
    };

    let mut details = Vec::new();
    if let Some(obj) = detail.as_object() {
        for (k, v) in obj {
            let val = if v.is_string() { v.as_str().unwrap_or("").to_string() } else { v.to_string() };
            if !val.is_empty() && val != "null" {
                details.push((k.replace('_', " "), val));
            }
        }
    }
    details.truncate(6);

    ActivityItem {
        id: raw.jti.clone().unwrap_or_default(),
        timestamp: ts,
        category,
        title,
        subtitle: raw.component.clone().unwrap_or_default(),
        status: "completed".to_string(),
        source: "host".to_string(),
        icon,
        risk_level: None,
        action_id: None,
        event_count: None,
        details,
    }
}

fn map_gateway_action(action: &serde_json::Value) -> ActivityItem {
    let action_id = action.get("action_id").and_then(|a| a.as_str()).unwrap_or("").to_string();
    let title = action.get("title").and_then(|t| t.as_str()).unwrap_or("Unknown action").to_string();
    let status = action.get("status").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();
    let risk = action.get("risk_level").and_then(|r| r.as_str()).map(|s| s.to_string());
    let source_type = action.get("source_type").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let event_count = action.get("event_count").and_then(|c| c.as_u64()).unwrap_or(0);
    let created = action.get("created_at").and_then(|c| c.as_str()).unwrap_or("").to_string();
    let action_name = action.get("action_name").and_then(|a| a.as_str()).unwrap_or("").to_string();
    let has_approval = action.get("approval_id").and_then(|a| a.as_str()).is_some();

    let ts = parse_iso_timestamp(&created);

    let subtitle = match status.as_str() {
        "executed" if has_approval => "Escalated → Approved → Executed",
        "executed" => "Auto-approved by policy → Executed",
        "denied" => "Blocked by policy",
        "failed" => "Execution failed",
        "waiting_approval" => "Waiting for human approval",
        "waiting_proof" => "Credential verification required",
        "approved" => "Approved, executing…",
        "retrying" => "Retrying dispatch…",
        "pending" => "Processing…",
        _ => "In progress",
    }.to_string();

    let icon = if action_name.contains("refund") { "🛒" }
        else if action_name.contains("calendar") { "📅" }
        else if action_name.contains("stripe") || action_name.contains("pay") { "💳" }
        else if action_name.contains("search") || action_name.contains("list") || action_name.contains("get") { "🔍" }
        else { "🔧" };

    let mut details = vec![
        ("Action".to_string(), action_name),
        ("Status".to_string(), status.clone()),
    ];
    if !source_type.is_empty() {
        details.push(("Source".to_string(), source_type));
    }
    if let Some(ref r) = risk {
        details.push(("Risk".to_string(), r.clone()));
    }

    ActivityItem {
        id: action_id.clone(),
        timestamp: ts,
        category: ActivityCategory::GovernanceAction,
        title,
        subtitle,
        status,
        source: "trust_gateway".to_string(),
        icon,
        risk_level: risk,
        action_id: Some(action_id),
        event_count: Some(event_count),
        details,
    }
}

fn parse_iso_timestamp(s: &str) -> u64 {
    if s.is_empty() { return 0; }
    (js_sys::Date::new(&s.into()).get_time() / 1000.0) as u64
}

// ─── Component ──────────────────────────────────────────────

#[component]
pub fn Activity(
    base_url: String,
    token: String,
) -> impl IntoView {
    let (items, set_items) = signal(Vec::<ActivityItem>::new());
    let (loading, set_loading) = signal(true);
    let (active_filter, set_active_filter) = signal("all".to_string());

    let base_clone = base_url.clone();
    let token_clone = token.clone();

    // Compute gateway URL
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

    // WS6.1: Dual-source fetch on mount
    Effect::new(move |_| {
        let base = base_clone.clone();
        let tok = token_clone.clone();
        let gw = gw_url.clone();
        set_loading.set(true);
        spawn_local(async move {
            let mut all_items = Vec::new();

            // Source 1: Host audit events
            if let Ok(host_events) = fetch_host_events(&base, &tok).await {
                all_items.extend(host_events);
            }

            // Source 2: Gateway governance actions
            if let Ok(gw_actions) = fetch_gateway_actions(&gw, &tok).await {
                all_items.extend(gw_actions);
            }

            all_items.sort_by_key(|i| std::cmp::Reverse(i.timestamp));
            set_items.set(all_items);
            set_loading.set(false);
        });
    });

    let (gw_sig, _) = signal(gateway_url);

    // WS6.4: Fixed stats — computed from unified model
    let stats = move || {
        let all = items.get();
        let governance = all.iter().filter(|i| i.category == ActivityCategory::GovernanceAction).count();
        let auto_approved = all.iter().filter(|i| {
            i.category == ActivityCategory::GovernanceAction && i.status == "executed"
        }).count();
        let human_decisions = all.iter().filter(|i| {
            i.category == ActivityCategory::GovernanceAction
                && (i.status == "waiting_approval" || i.status == "approved" || i.status == "denied")
        }).count();
        let denied_failed = all.iter().filter(|i| {
            i.category == ActivityCategory::GovernanceAction
                && (i.status == "denied" || i.status == "failed")
        }).count();
        (governance, auto_approved, human_decisions, denied_failed)
    };

    // Filtered stream
    let filtered_items = move || {
        let filter = active_filter.get();
        let all = items.get();
        if filter == "all" { return all; }
        all.into_iter().filter(|item| {
            match filter.as_str() {
                "governance" => item.category == ActivityCategory::GovernanceAction,
                "agent" => item.category == ActivityCategory::AgentActivity,
                "auth" => item.category == ActivityCategory::Authentication,
                "messages" => item.category == ActivityCategory::Messaging,
                _ => true,
            }
        }).collect()
    };

    view! {
        <div class="space-y-6 max-w-6xl mx-auto">
            // Header
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-slate-900 border border-slate-700/50 p-6 rounded-2xl shadow-2xl relative overflow-hidden">
                <div class="absolute inset-0 bg-grid-slate-800/[0.2] bg-[size:16px_16px]"></div>
                <div class="absolute -top-24 -right-24 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl"></div>
                <div class="absolute -bottom-24 -left-24 w-48 h-48 bg-amber-500/10 rounded-full blur-3xl"></div>

                <div class="relative z-10">
                    <h1 class="text-3xl font-bold text-white tracking-tight flex items-center gap-2">
                        <span class="text-cyan-400">"📊"</span> "Activity Feed"
                    </h1>
                    <p class="text-sm text-slate-400 mt-1 ml-8">"Real-time view of all system activity"</p>
                </div>

                <div class="relative z-10 flex items-center gap-4">
                    <button
                        class="flex items-center gap-2 px-4 py-2 rounded-full text-sm font-bold transition-all bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 hover:border-slate-500"
                        on:click={
                            let base_r = base_url.clone();
                            let tok_r = token.clone();
                            move |_| {
                                let b = base_r.clone();
                                let t = tok_r.clone();
                                let g = gw_sig.get();
                                spawn_local(async move {
                                    set_loading.set(true);
                                    let mut all_items = Vec::new();
                                    if let Ok(h) = fetch_host_events(&b, &t).await { all_items.extend(h); }
                                    if let Ok(g) = fetch_gateway_actions(&g, &t).await { all_items.extend(g); }
                                    all_items.sort_by_key(|i| std::cmp::Reverse(i.timestamp));
                                    set_items.set(all_items);
                                    set_loading.set(false);
                                });
                            }
                        }
                    >
                        <span class="relative flex h-2.5 w-2.5 mr-1">
                            <span class="absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-20"></span>
                            <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
                        </span>
                        "REFRESH"
                    </button>
                    <div class=move || format!("text-xs font-bold tracking-widest uppercase transition-opacity {}", if loading.get() { "opacity-100 text-cyan-400 animate-pulse" } else { "opacity-0" })>
                        "Fetching..."
                    </div>
                </div>
            </div>

            // WS6.4: Stats
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard title="Governance Actions" value=move || stats().0.to_string() icon="🔒" color="blue" />
                <StatCard title="Auto-Approved" value=move || stats().1.to_string() icon="⚡" color="green" />
                <StatCard title="Human Decisions" value=move || stats().2.to_string() icon="⏳" color="amber" />
                <StatCard title="Denied / Failed" value=move || stats().3.to_string() icon="🚫" color="red" />
            </div>

            // WS6.3: Category Filter Tabs
            <div class="flex gap-2 overflow-x-auto pb-2">
                {["all", "governance", "agent", "auth", "messages"].into_iter().map(|tab| {
                    let tab_str = tab.to_string();
                    let label = match tab {
                        "all" => "All",
                        "governance" => "🔒 Governance",
                        "agent" => "🧠 Agent",
                        "auth" => "🔑 Auth",
                        "messages" => "💬 Messages",
                        _ => tab,
                    };
                    view! {
                        <button
                            on:click=move |_| set_active_filter.set(tab_str.clone())
                            class=move || format!(
                                "px-4 py-2 rounded-lg text-sm font-bold transition-all whitespace-nowrap {}",
                                if active_filter.get() == tab {
                                    "bg-cyan-600 text-white shadow-lg shadow-cyan-900/40"
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

            // Loading
            <Show when=move || loading.get() && items.get().is_empty()>
                <div class="flex items-center justify-center py-20">
                    <div class="relative w-16 h-16">
                        <div class="absolute inset-0 border-t-2 border-cyan-500 rounded-full animate-spin"></div>
                        <div class="absolute inset-2 border-r-2 border-purple-500 rounded-full animate-spin"></div>
                    </div>
                </div>
            </Show>

            // Empty state
            <Show when=move || !loading.get() && items.get().is_empty()>
                <div class="bg-black/20 rounded-2xl p-16 text-center border border-slate-800/50 backdrop-blur-md">
                    <div class="w-20 h-20 bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-6 border border-slate-700">
                        <span class="text-3xl text-slate-500">"📊"</span>
                    </div>
                    <p class="text-xl font-medium text-slate-300 mb-2">"No activity yet"</p>
                    <p class="text-sm text-slate-500 max-w-md mx-auto">"Trigger actions in the agent or gateway to see activity here."</p>
                </div>
            </Show>

            // Activity stream
            <div class="space-y-3">
                {move || {
                    filtered_items().into_iter().map(|item| {
                        view! { <ActivityCard item=item gateway_url=gw_sig.get() /> }
                    }).collect_view()
                }}
            </div>
        </div>
    }
}

// ─── Activity Card Component (WS6.3 + WS6.5) ───────────────

#[component]
fn ActivityCard(item: ActivityItem, gateway_url: String) -> impl IntoView {
    let is_governance = item.category == ActivityCategory::GovernanceAction;
    let has_replay = item.action_id.is_some();

    let status_class = match item.status.as_str() {
        "executed" => "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
        "approved" => "bg-green-500/20 text-green-400 border-green-500/30",
        "denied" | "failed" => "bg-red-500/20 text-red-400 border-red-500/30",
        "waiting_approval" | "waiting_proof" | "pending" | "retrying" => "bg-amber-500/20 text-amber-400 border-amber-500/30",
        "completed" => "bg-slate-500/20 text-slate-400 border-slate-500/30",
        _ => "bg-slate-500/20 text-slate-400 border-slate-500/30",
    };

    let risk_badge = match item.risk_level.as_deref() {
        Some("high") | Some("critical") => Some(("⚡ HIGH", "bg-orange-500/20 text-orange-400 border-orange-500/30")),
        Some("medium") => Some(("⚡ MED", "bg-amber-500/20 text-amber-400 border-amber-500/30")),
        Some("low") => Some(("✅ LOW", "bg-green-500/20 text-green-400 border-green-500/30")),
        _ => None,
    };

    let border_color = if is_governance {
        "border-cyan-500/20 hover:border-cyan-500/40"
    } else {
        "border-slate-700/50 hover:border-slate-600"
    };

    let progress = if is_governance {
        let count = item.event_count.unwrap_or(0);
        let total = 7u64;
        let pct = ((count as f64 / total as f64) * 100.0).min(100.0);
        Some((count, pct))
    } else {
        None
    };

    view! {
        <div class=format!("bg-[#0A0D14] border {} rounded-xl p-4 transition-all", border_color)>
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
                // Left: Icon + Title + Subtitle
                <div class="flex items-start gap-3 flex-1 min-w-0">
                    <div class="text-2xl w-10 h-10 flex items-center justify-center bg-black/40 rounded-lg border border-slate-800 shrink-0">
                        {item.icon}
                    </div>
                    <div class="min-w-0">
                        <div class="flex items-center gap-2 flex-wrap mb-1">
                            <span class="font-bold text-white text-sm truncate">{item.title.clone()}</span>
                            <span class=format!("px-2 py-0.5 rounded text-[10px] font-bold uppercase border {}", status_class)>
                                {item.status.clone()}
                            </span>
                            {risk_badge.map(|(label, classes)| view! {
                                <span class=format!("px-2 py-0.5 rounded text-[10px] font-bold border {}", classes)>
                                    {label}
                                </span>
                            })}
                        </div>
                        <p class="text-xs text-slate-500">{item.subtitle.clone()}</p>
                        // Governance progress bar
                        {progress.map(|(count, pct)| view! {
                            <div class="mt-2 flex items-center gap-2">
                                <div class="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden max-w-[200px]">
                                    <div
                                        class="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all"
                                        style=format!("width: {}%", pct)
                                    ></div>
                                </div>
                                <span class="text-[10px] text-slate-500">{format!("{} events", count)}</span>
                            </div>
                        })}
                    </div>
                </div>

                // Right: Timestamp + Actions
                <div class="flex items-center gap-4 shrink-0">
                    <span class="text-xs text-slate-500">{format_ts(item.timestamp)}</span>
                    {if has_replay {
                        Some(view! {
                            <a
                                href="#trust-replay"
                                class="text-[10px] font-bold text-cyan-500 hover:text-cyan-400 transition-colors whitespace-nowrap"
                            >
                                "View Replay →"
                            </a>
                        })
                    } else { None }}
                    // WS6.5: Structured detail panel (replaces raw JSON PAYLOAD)
                    <details class="group cursor-pointer">
                        <summary class="list-none text-xs font-mono text-cyan-500/70 hover:text-cyan-400 bg-cyan-950/30 px-3 py-1.5 rounded border border-cyan-900/50 transition-colors">
                            "Details ▾"
                        </summary>
                        <div class="absolute right-0 md:right-auto mt-2 w-[calc(100vw-2rem)] md:w-[400px] bg-[#050505] border border-cyan-900/50 rounded-xl p-4 shadow-2xl z-50">
                            <div class="mb-2 pb-2 border-b border-slate-800 text-xs text-slate-500 font-mono">"event.details"</div>
                            <div class="space-y-2">
                                {item.details.into_iter().map(|(k, v)| {
                                    view! {
                                        <div class="flex items-start gap-2 text-xs">
                                            <span class="text-slate-500 font-medium w-24 shrink-0">{k}</span>
                                            <span class="text-slate-300 break-all">{v}</span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    </details>
                </div>
            </div>
        </div>
    }
}

// ─── Stat Card ──────────────────────────────────────────────

#[component]
fn StatCard(title: &'static str, value: impl Fn() -> String + Send + Sync + 'static, icon: &'static str, color: &'static str) -> impl IntoView {
    let bg_color = match color {
        "blue" => "bg-blue-500/10 border-blue-500/20 text-blue-400",
        "green" => "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
        "amber" => "bg-amber-500/10 border-amber-500/20 text-amber-400",
        "red" => "bg-red-500/10 border-red-500/20 text-red-400",
        "purple" => "bg-purple-500/10 border-purple-500/20 text-purple-400",
        _ => "bg-slate-800/50 border-slate-700 text-slate-300"
    };

    view! {
        <div class=format!("p-5 rounded-2xl border backdrop-blur-md {}", bg_color)>
            <div class="flex items-center justify-between mb-4">
                <span class="text-sm font-medium tracking-wide opacity-80">{title}</span>
                <span class="text-xl opacity-80">{icon}</span>
            </div>
            <div class="text-3xl font-bold tracking-tight">
                {move || value()}
            </div>
        </div>
    }
}

// ─── Data Fetching (WS6.1) ─────────────────────────────────

async fn fetch_host_events(base: &str, tok: &str) -> Result<Vec<ActivityItem>, String> {
    let url = format!("{}/tenant/current/audit/export?limit=200", base);
    log::debug!("🌐 Activity: Fetching Host events from {} (tok len={})", url, tok.len());
    let resp = reqwasm::http::Request::get(&url)
        .header("Authorization", &format!("Bearer {}", tok))
        .send()
        .await
        .map_err(|e| format!("{}", e))?;

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("{}", e))?;

    let mut items = Vec::new();
    if let Some(events) = data.get("events").and_then(|v| v.as_array()) {
        for evt in events {
            if let Ok(raw) = serde_json::from_value::<HostEventRaw>(evt.clone()) {
                items.push(map_host_event(&raw));
            }
        }
    }
    Ok(items)
}

async fn fetch_gateway_actions(gateway_url: &str, tok: &str) -> Result<Vec<ActivityItem>, String> {
    let url = format!("{}/api/actions?limit=50", gateway_url);
    log::debug!("🌐 Activity: Fetching Gateway actions from {} (tok len={})", url, tok.len());
    let resp = reqwasm::http::Request::get(&url)
        .header("Authorization", &format!("Bearer {}", tok))
        .send()
        .await
        .map_err(|e| format!("{}", e))?;

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("{}", e))?;

    let mut items = Vec::new();
    if let Some(actions) = data.get("actions").and_then(|v| v.as_array()) {
        for action in actions {
            items.push(map_gateway_action(action));
        }
    }
    Ok(items)
}

fn format_ts(ts: u64) -> String {
    if ts == 0 { return "—".to_string(); }
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let diff = now.saturating_sub(ts);
    if diff < 60 { format!("{}s ago", diff) }
    else if diff < 3600 { format!("{}m ago", diff / 60) }
    else if diff < 86400 { format!("{}h ago", diff / 3600) }
    else { format!("{}d ago", diff / 86400) }
}
