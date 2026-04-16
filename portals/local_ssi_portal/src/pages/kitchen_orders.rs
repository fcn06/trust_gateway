use leptos::prelude::*;
use reqwasm::http::Request;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;



#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OrderItem {
    pub item_id: String,
    pub name: String,
    pub quantity: u32,
    pub unit_price: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OrderState {
    pub order_id: String,
    pub status: String,
    pub table_number: u32,
    pub items: Vec<OrderItem>,
    pub total: f64,
    pub payment_link: Option<String>,
}

#[component]
pub fn KitchenOrders(
    config: crate::types::PortalConfig,
    identities: ReadSignal<Vec<crate::types::EnrichedIdentity>>,
    registration_cookie: ReadSignal<Option<crate::types::RegistrationCookie>>,
) -> impl IntoView {
    let base_url = store_value(config.api_base_url.clone());

    let active_tenant = Memo::new(move |_| {
        // Use the real tenant_id from the registration cookie.
        // This is populated by the host from the tenant_registry during
        // registration/login. Falls back gracefully for legacy sessions.
        registration_cookie.get()
            .and_then(|c| c.tenant_id.clone())
            .unwrap_or_else(|| {
                registration_cookie.get()
                    .map(|c| c.aid.clone())
                    .unwrap_or_else(|| "anonymous".to_string())
            })
    });

    let (orders, set_orders) = signal(Vec::<OrderState>::new());
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(String::new());

    let load_orders = move || {
        spawn_local(async move {
            set_loading.set(true);
            set_error_msg.set(String::new());

            let current_tenant = active_tenant.get();
            let req = json!({
                "action_id": format!("ui_{}", js_sys::Math::random().to_string().replace(".", "")),
                "skill_name": "restaurant_orders_list",
                "arguments": {},
                "tenant_id": "rest_demo"
            });

            match Request::post(&format!("{}/restaurant/invoke", base_url.get_value()))
                .credentials(reqwasm::http::RequestCredentials::Include)
                .header("Content-Type", "application/json")
                .body(serde_json::to_string(&req).unwrap())
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.ok() {
                        if let Ok(text) = resp.text().await {
                            if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
                                let success = parsed.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
                                if success {
                                    if let Some(orders_val) = parsed.get("output").and_then(|o| o.get("orders")) {
                                        if let Ok(order_list) = serde_json::from_value::<Vec<OrderState>>(orders_val.clone()) {
                                            let mut active_orders = order_list;
                                            // Only show submitted and cooking orders
                                            active_orders.retain(|o| o.status == "submitted" || o.status == "kitchen_confirmed");
                                            set_orders.set(active_orders);
                                        }
                                    }
                                } else {
                                    set_error_msg.set(parsed.get("error").and_then(|e| e.as_str()).unwrap_or("Unknown error").to_string());
                                }
                            }
                        }
                    } else {
                        set_error_msg.set(format!("HTTP Error: {}", resp.status()));
                    }
                }
                Err(e) => set_error_msg.set(format!("Network Error: {}", e)),
            }
            set_loading.set(false);
        });
    };

    let confirm_order = move |order_id: String| {
        let current_tenant = active_tenant.get();
        spawn_local(async move {
            let req = json!({
                "action_id": format!("ui_{}", js_sys::Math::random().to_string().replace(".", "")),
                "skill_name": "restaurant_order_confirm",
                "arguments": {
                    "order_id": order_id
                },
                "tenant_id": "rest_demo"
            });

            if let Ok(resp) = Request::post(&format!("{}/restaurant/invoke", base_url.get_value()))
                .credentials(reqwasm::http::RequestCredentials::Include)
                .header("Content-Type", "application/json")
                .body(serde_json::to_string(&req).unwrap())
                .send()
                .await
            {
                if resp.ok() {
                    load_orders();
                }
            }
        });
    };

    // Initial load
    let load_init = load_orders.clone();
    Effect::new(move |_| {
        load_init();
    });

    view! {
        <div class="space-y-6 max-w-7xl mx-auto pb-12">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-700/50 pb-6">
                <div>
                    <h1 class="text-3xl font-bold bg-gradient-to-r from-orange-400 to-rose-500 bg-clip-text text-transparent">
                        "Kitchen Display System"
                    </h1>
                    <p class="text-slate-400 text-sm mt-1">"Manage active orders and print tickets."</p>
                </div>
                <button
                    on:click=move |_| load_orders()
                    class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors text-sm font-medium shadow-sm border border-slate-600 flex items-center gap-2"
                >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    "Refresh Orders"
                </button>
            </div>

            <Show when=move || !error_msg.get().is_empty()>
                <div class="bg-red-900/30 border border-red-500/30 rounded-xl p-4 text-red-300 shadow-sm flex items-start gap-3">
                    <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <p>{move || error_msg.get()}</p>
                </div>
            </Show>

            <Show when=move || loading.get()>
                <div class="text-center py-12 text-orange-400 absolute w-full top-32 pointer-events-none">
                    <div class="animate-spin h-8 w-8 border-4 border-orange-500 border-t-transparent rounded-full mx-auto"></div>
                </div>
            </Show>

            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {move || orders.get().into_iter().map(move |order| {
                    let is_submitted = order.status == "submitted";
                    
                    let bg_color = if is_submitted { "bg-slate-800/80 border-orange-500/50 shadow-orange-900/20" } else { "bg-slate-800/50 border-emerald-500/30 opacity-80" };
                    let header_bg = if is_submitted { "bg-gradient-to-r from-orange-600/20 to-rose-600/20" } else { "bg-gradient-to-r from-emerald-600/20 to-teal-600/20" };
                    let time_badge = if is_submitted { "text-orange-400 bg-orange-500/10 border border-orange-500/30" } else { "text-emerald-400 bg-emerald-500/10 border border-emerald-500/30" };
                    
                    let order_id = order.order_id.clone();

                    view! {
                        <div class=format!("rounded-2xl border transition-all shadow-lg overflow-hidden flex flex-col {}", bg_color)>
                            // Ticket Header
                            <div class=format!("p-4 border-b border-slate-700/50 flex justify-between items-center {}", header_bg)>
                                <div class="flex items-center gap-3">
                                    <div class="w-10 h-10 rounded-full bg-slate-900 border border-slate-700 flex flex-col items-center justify-center">
                                        <span class="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-[-2px]">"TBL"</span>
                                        <span class="text-base font-bold text-white leading-none">{order.table_number.to_string()}</span>
                                    </div>
                                    <div>
                                        <h3 class="font-bold text-lg text-white">
                                            {format!("Order #{}", &order.order_id.chars().take(6).collect::<String>())}
                                        </h3>
                                        <p class="text-xs text-slate-400 font-mono">{order.order_id.clone()}</p>
                                    </div>
                                </div>
                                <div class=format!("px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 {}", time_badge)>
                                    {if is_submitted { 
                                        view!{ <><span class="w-1.5 h-1.5 rounded-full bg-orange-500 animate-ping"></span> "New"</> }.into_any()
                                    } else { 
                                        view!{ <><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> "Cooking"</> }.into_any()
                                    }}
                                </div>
                            </div>
                            
                            // Ticket Items
                            <div class="p-5 flex-1 bg-slate-900/30">
                                <ul class="space-y-4">
                                    {order.items.into_iter().map(|item| {
                                        view! {
                                            <li class="flex items-start gap-4">
                                                <div class="w-8 h-8 rounded shrink-0 bg-slate-700 border border-slate-600 flex items-center justify-center font-bold text-slate-200">
                                                    {format!("{}x", item.quantity)}
                                                </div>
                                                <div class="pt-1">
                                                    <p class="font-medium text-slate-200 text-lg leading-tight">{item.name}</p>
                                                </div>
                                            </li>
                                        }
                                    }).collect_view()}
                                </ul>
                            </div>
                            
                            // Ticket Footer & Actions
                            <div class="p-4 border-t border-slate-700/50 bg-slate-800 flex justify-between items-center">
                                <span class="font-bold text-slate-400">
                                    "Total: €"{format!("{:.2}", order.total)}
                                </span>
                                
                                <Show when=move || is_submitted>
                                    <button
                                        on:click={
                                            let id = order_id.clone();
                                            move |_| confirm_order(id.clone())
                                        }
                                        class="px-6 py-2.5 bg-gradient-to-r from-orange-500 to-rose-500 hover:from-orange-400 hover:to-rose-400 text-white font-bold rounded-lg shadow-lg shadow-rose-500/20 active:scale-95 transition-all text-sm uppercase tracking-wider"
                                    >
                                        "Start Cooking"
                                    </button>
                                </Show>
                            </div>
                        </div>
                    }
                }).collect_view()}
            </div>

            <Show when=move || !loading.get() && orders.get().is_empty() && error_msg.get().is_empty()>
                <div class="bg-slate-800/30 rounded-2xl p-16 text-center border text-slate-500 border-dashed border-slate-700 max-w-2xl mx-auto mt-12">
                    <div class="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-6">
                        <svg class="w-10 h-10 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                    </div>
                    <p class="text-slate-300 text-xl font-medium mb-2">"No active tickets."</p>
                    <p class="text-slate-400">"All orders are completed or none have been submitted yet. Go stretch your legs!"</p>
                </div>
            </Show>
        </div>
    }
}
