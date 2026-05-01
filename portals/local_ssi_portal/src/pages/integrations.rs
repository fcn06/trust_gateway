//! Integrations page — manage OAuth connector status (Google, Stripe, Shopify).

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::RegistrationCookie;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStatus {
    pub provider: String,
    pub connected: bool,
    pub scopes: Vec<String>,
    pub connected_at: Option<i64>,
}

#[component]
pub fn Integrations(
    base_url: String,
    connector_url: Option<String>,
    token: String,
    registration_cookie: ReadSignal<Option<RegistrationCookie>>,
) -> impl IntoView {
    // If connector_url is not explicitly provided, fall back to inferring it from base_url
    let connector_url = connector_url.unwrap_or_else(|| {
        base_url.trim_end_matches("/api").trim_end_matches('/').to_string()
    });

    let (statuses, set_statuses) = signal(HashMap::<String, IntegrationStatus>::new());
    let (loading, set_loading) = signal(true);

    // Fetch integration status on mount
    let connector_for_fetch = connector_url.clone();
    Effect::new(move |_| {
        let connector = connector_for_fetch.clone();
        if let Some(cookie) = registration_cookie.get() {
            let tenant_id = cookie.tenant_id.clone()
                .unwrap_or_else(|| cookie.aid.clone());
            spawn_local(async move {
                set_loading.set(true);
                let url = format!("{}/oauth/status/{}", connector, tenant_id);
                match reqwasm::http::Request::get(&url).send().await {
                    Ok(resp) => {
                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                            if let Some(list) = data.get("integrations").and_then(|v| v.as_array()) {
                                let mut map = HashMap::new();
                                for item in list {
                                    if let Ok(status) = serde_json::from_value::<IntegrationStatus>(item.clone()) {
                                        map.insert(status.provider.clone(), status);
                                    }
                                }
                                set_statuses.set(map);
                            }
                        }
                    }
                    Err(e) => log::warn!("Failed to fetch integration status: {:?}", e),
                }
                set_loading.set(false);
            });
        } else {
            set_loading.set(false);
        }
    });

    let integrations = vec![
        ("Google Calendar", "google", "📅", "Sync your calendar events for AI-assisted scheduling", "bg-gradient-to-br from-blue-600 to-blue-800", true),
        ("Stripe", "stripe", "💳", "View payment statuses and manage transactions via AI", "bg-gradient-to-br from-purple-600 to-indigo-800", false),
        ("Shopify", "shopify", "🛒", "Track orders and inventory with AI-powered insights", "bg-gradient-to-br from-green-600 to-teal-800", false),
    ];

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                    "🔗 Integrations"
                </h1>
                <span class="text-xs text-gray-500 bg-slate-800 px-3 py-1 rounded-full">"Powered by MCP"</span>
            </div>

            <p class="text-gray-400 text-sm">
                "Connect third-party services to give your AI agent access to your business tools."
            </p>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {integrations.into_iter().map(|(name, provider, icon, desc, gradient, enabled)| {
                    let provider_clone = provider.to_string();
                    let provider_for_status = provider.to_string();
                    let connector_url_clone = connector_url.clone();
                    view! {
                        <div class=format!("rounded-2xl p-6 border border-slate-600/50 hover:border-slate-400/50 transition-all {}", gradient)>
                            <div class="flex items-center gap-3 mb-4">
                                <span class="text-3xl">{icon}</span>
                                <div>
                                    <h3 class="text-lg font-bold text-white">{name}</h3>
                                    {move || {
                                        let provider_key = provider_for_status.clone();
                                        if loading.get() {
                                            view! { <span class="text-xs text-gray-300/70">"Checking..."</span> }.into_any()
                                        } else if statuses.get().get(&provider_key).map(|s| s.connected).unwrap_or(false) {
                                            view! { <span class="text-xs text-green-400 font-semibold">"✓ Connected"</span> }.into_any()
                                        } else {
                                            view! { <span class="text-xs text-gray-300/70">"Not connected"</span> }.into_any()
                                        }
                                    }}
                                </div>
                            </div>
                            <p class="text-sm text-gray-200/80 mb-6">{desc}</p>
                            {if enabled {
                                let provider_for_click = provider_clone.clone();
                                let provider_for_btn = provider_clone.clone();
                                let connector_for_click = connector_url_clone.clone();
                                view! {
                                    {move || {
                                        let is_connected = statuses.get().get(&provider_for_btn).map(|s| s.connected).unwrap_or(false);
                                        if is_connected {
                                            view! {
                                                <button
                                                    disabled=true
                                                    class="w-full bg-emerald-500/20 text-emerald-400 font-bold py-2 px-4 rounded-lg border border-emerald-500/50 cursor-default flex items-center justify-center gap-2"
                                                >
                                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                                                    "Connected"
                                                </button>
                                            }.into_any()
                                        } else {
                                            let prov = provider_for_click.clone();
                                            let conn = connector_for_click.clone();
                                            view! {
                                                <button
                                                    on:click=move |_| {
                                                        if let Some(cookie) = registration_cookie.get() {
                                                            let url = format!("{}/oauth/{}/authorize/{}", conn, prov, cookie.tenant_id.clone().unwrap_or_else(|| cookie.aid.clone()));
                                                            if let Some(win) = web_sys::window() {
                                                                let _ = win.open_with_url(&url);
                                                            }
                                                        }
                                                    }
                                                    class="w-full bg-white/10 hover:bg-white/20 text-white font-medium py-2 px-4 rounded-lg transition-all border border-white/20 hover:border-white/40"
                                                >
                                                    "Connect"
                                                </button>
                                            }.into_any()
                                        }
                                    }}
                                }.into_any()
                            } else {
                                view! {
                                    <button
                                        on:click=move |_| {
                                            if let Some(win) = web_sys::window() {
                                                let _ = win.alert_with_message("You have been added to the waitlist!");
                                            }
                                        }
                                        class="w-full bg-white/10 hover:bg-white/20 text-white font-medium py-2 px-4 rounded-lg transition-all border border-white/20 hover:border-white/40"
                                    >
                                        "Notify Me"
                                    </button>
                                }.into_any()
                            }}
                        </div>
                    }
                }).collect_view()}
            </div>

            <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mt-8">
                <h3 class="text-lg font-semibold text-white mb-3">"🔒 Security"</h3>
                <ul class="space-y-2 text-sm text-gray-400">
                    <li class="flex items-center gap-2">
                        <span class="text-green-400">"✓"</span>
                        "OAuth tokens are tenant-scoped and stored in encrypted KV"
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="text-green-400">"✓"</span>
                        "Access is read-only by default. Mutations require escalation approval"
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="text-green-400">"✓"</span>
                        "All API calls are logged in the audit trail"
                    </li>
                </ul>
            </div>
        </div>
    }
}
