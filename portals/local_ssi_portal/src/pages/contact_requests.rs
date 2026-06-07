//! Contact Requests page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::{ContactRequest, EnrichedIdentity};

#[component]
pub fn ContactRequestsSection(
    base_url: String, 
    token: String, 
    identities: ReadSignal<Vec<EnrichedIdentity>>,
    refresh_trigger: ReadSignal<i32>,
    set_refresh_trigger: WriteSignal<i32>,
    policies: ReadSignal<Vec<crate::types::ConnectionPolicy>>,
) -> impl IntoView {
    let (target_did, set_target_did) = signal(String::new());
    let (msg_body, set_msg_body) = signal(String::new());
    let (is_sending, set_is_sending) = signal(false);
    let (error, set_error) = signal(Option::<String>::None);
    let (success, set_success) = signal(Option::<String>::None);
    let (is_offline, set_is_offline) = signal(false);
    
    let (requests, set_requests) = signal(Vec::<ContactRequest>::new());
    
    let base_url = store_value(base_url);
    let token = store_value(token);
    
    Effect::new(move |_| {
        let ab = base_url.get_value();
        let tt = token.get_value();
        let _ = refresh_trigger.get();
        spawn_local(async move {
            if let Ok(list) = api::get_contact_requests(&ab, tt).await {
                set_requests.set(list);
            }
        });
    });

    let on_send_request = move |_| {
        let did = target_did.get();
        let body = msg_body.get();
        if did.is_empty() {
            set_error.set(Some("Target DID is required".to_string()));
            return;
        }
        
        set_is_sending.set(true);
        set_error.set(None);
        set_success.set(None);
        
        let ab = base_url.get_value();
        let tt = token.get_value();
        
        spawn_local(async move {
            if is_offline.get() {
                let req = crate::types::SendLedgerlessRequest {
                    target_did: did,
                    message: body,
                };
                match api::send_ledgerless_request(&ab, req, tt).await {
                    Ok(_) => {
                        set_success.set(Some("Offline connection request sent!".to_string()));
                        set_target_did.set(String::new());
                        set_msg_body.set(String::new());
                        set_refresh_trigger.update(|n| *n += 1);
                    },
                    Err(e) => set_error.set(Some(format!("Failed to send: {}", e))),
                }
            } else {
                let req = crate::types::SendMessageRequest {
                    to: did,
                    body,
                    r#type: "https://lianxi.io/protocols/contact/1.0/request".to_string(),
                    thid: None,
                };
                match api::send_message(&ab, req, tt).await {
                    Ok(_) => {
                        set_success.set(Some("Contact request sent successfully!".to_string()));
                        set_target_did.set(String::new());
                        set_msg_body.set(String::new());
                        set_refresh_trigger.update(|n| *n += 1);
                    },
                    Err(e) => set_error.set(Some(format!("Failed to send: {}", e))),
                }
            }
            set_is_sending.set(false);
        });
    };

    view! {
        <div class="space-y-6 text-white max-w-[1400px] mx-auto">
            <h2 class="text-2xl font-bold">"Connections"</h2>
            
            <Show when=move || error.get().is_some()>
                <div class="p-4 bg-red-900/30 border border-red-500/50 rounded-xl text-red-400">
                    {move || error.get()}
                </div>
            </Show>
            
            <Show when=move || success.get().is_some()>
                <div class="p-4 bg-green-900/30 border border-green-500/50 rounded-xl text-green-400">
                    {move || success.get()}
                </div>
            </Show>

            // Send Contact Request Form
            <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl space-y-4">
                <h3 class="text-lg font-semibold">"Send Connection Request"</h3>
                
                <Show 
                    when=move || is_offline.get()
                    fallback=move || view! {
                        <div class="space-y-4">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div class="space-y-1">
                                    <input 
                                        type="text" 
                                        placeholder="e.g. alice or alice@company.com"
                                        prop:value=move || target_did.get()
                                        on:input=move |e| set_target_did.set(event_target_value(&e))
                                        class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none w-full text-white"
                                    />
                                    <p class="text-xs text-slate-500 pl-1">"Enter the username of the person you want to connect with."</p>
                                </div>
                                <div class="space-y-1">
                                    <input 
                                        type="text" 
                                        placeholder="Message (e.g. Hi, let's connect!)"
                                        prop:value=move || msg_body.get()
                                        on:input=move |e| set_msg_body.set(event_target_value(&e))
                                        class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none w-full text-white"
                                    />
                                    <p class="text-xs text-slate-500 pl-1">"Include a personal note to introduce yourself."</p>
                                </div>
                            </div>
                            
                            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-2">
                                <button 
                                    on:click=on_send_request
                                    disabled=move || is_sending.get()
                                    class="bg-blue-600 hover:bg-blue-500 px-6 py-2 rounded-lg font-bold transition-all disabled:opacity-50 text-sm shadow-md"
                                >
                                    {move || if is_sending.get() { "Sending..." } else { "Send Request" }}
                                </button>
                                
                                <details class="group">
                                    <summary class="text-xs text-slate-500 cursor-pointer list-none hover:text-slate-300 transition-colors flex items-center gap-1">
                                        <span>"Advanced Connection Options"</span>
                                        <svg class="w-3.5 h-3.5 text-slate-500 transform group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                                    </summary>
                                    <div class="mt-2 p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-3">
                                        <p class="text-xs text-slate-400">"Choose 'Direct Connection' to connect using an offline or non-public identity."</p>
                                        <div class="flex gap-2 bg-slate-950 p-1 rounded-lg w-max border border-slate-850">
                                            <button 
                                                on:click=move |_| set_is_offline.set(false)
                                                class=move || format!("px-3 py-1 rounded text-xs font-bold transition-all {}", 
                                                    if !is_offline.get() { "bg-blue-600/30 text-blue-400" } else { "text-slate-500 hover:text-slate-300" })
                                            >
                                                "Standard Connection"
                                            </button>
                                            <button 
                                                on:click=move |_| set_is_offline.set(true)
                                                class=move || format!("px-3 py-1 rounded text-xs font-bold transition-all {}", 
                                                    if is_offline.get() { "bg-purple-600/30 text-purple-400" } else { "text-slate-500 hover:text-slate-300" })
                                            >
                                                "Direct Connection"
                                            </button>
                                        </div>
                                    </div>
                                </details>
                            </div>
                        </div>
                    }
                >
                    <div class="space-y-4">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div class="space-y-1">
                                <input 
                                    type="text" 
                                    placeholder="Recipient (e.g. domain name or unique ID)"
                                    prop:value=move || target_did.get()
                                    on:input=move |e| set_target_did.set(event_target_value(&e))
                                    class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-purple-500 outline-none w-full text-white"
                                />
                                <p class="text-xs text-slate-500 pl-1">"Enter the network ID or offline identity identifier."</p>
                            </div>
                            <div class="space-y-1">
                                <input 
                                    type="text" 
                                    placeholder="Initial Message (Optional)"
                                    prop:value=move || msg_body.get()
                                    on:input=move |e| set_msg_body.set(event_target_value(&e))
                                    class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-purple-500 outline-none w-full text-white"
                                />
                                <p class="text-xs text-slate-500 pl-1">"Add an optional message to accompany the direct link."</p>
                            </div>
                        </div>
                        
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-2">
                            <button 
                                on:click=on_send_request
                                disabled=move || is_sending.get()
                                class="bg-purple-600 hover:bg-purple-500 px-6 py-2 rounded-lg font-bold transition-all disabled:opacity-50 text-sm shadow-md"
                            >
                                {move || if is_sending.get() { "Sending..." } else { "Send Secure Request" }}
                            </button>
                            
                            <details class="group" open=true>
                                <summary class="text-xs text-slate-500 cursor-pointer list-none hover:text-slate-300 transition-colors flex items-center gap-1">
                                    <span>"Advanced Connection Options"</span>
                                    <svg class="w-3.5 h-3.5 text-slate-500 transform group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                                </summary>
                                <div class="mt-2 p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-3">
                                    <p class="text-xs text-slate-400">"Choose 'Standard Connection' to search by username on the public ledger."</p>
                                    <div class="flex gap-2 bg-slate-950 p-1 rounded-lg w-max border border-slate-800">
                                        <button 
                                            on:click=move |_| set_is_offline.set(false)
                                            class=move || format!("px-3 py-1 rounded text-xs font-bold transition-all {}", 
                                                if !is_offline.get() { "bg-blue-600/30 text-blue-400" } else { "text-slate-500 hover:text-slate-300" })
                                        >
                                            "Standard Connection"
                                        </button>
                                        <button 
                                            on:click=move |_| set_is_offline.set(true)
                                            class=move || format!("px-3 py-1 rounded text-xs font-bold transition-all {}", 
                                                if is_offline.get() { "bg-purple-600/30 text-purple-400" } else { "text-slate-500 hover:text-slate-300" })
                                        >
                                            "Direct Connection"
                                        </button>
                                    </div>
                                </div>
                            </details>
                        </div>
                    </div>
                </Show>
            </div>

            // Connection Requests List
            <div class="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden shadow-2xl">
                <div class="p-4 border-b border-slate-700 flex justify-between items-center">
                    <h3 class="text-lg font-semibold">"Connection Requests"</h3>
                    <button 
                        on:click=move |_| set_refresh_trigger.update(|n| *n += 1)
                        class="text-xs text-blue-400 hover:text-blue-300"
                    >
                        "Refresh"
                    </button>
                </div>
                <Show 
                    when=move || !requests.get().is_empty()
                    fallback=move || view! {
                        <div class="p-8 text-center text-slate-500 italic">
                            "No connection requests yet."
                        </div>
                    }
                >
                    <div class="grid gap-4 p-4">
                        <For
                            each=move || requests.get()
                            key=|r| format!("{}_{}", r.id, r.status)
                            children=move |req| {
                                let id = req.id.clone();
                                let id_accept = id.clone();
                                let id_refuse = id.clone();
                                
                                let is_incoming_role = req.role.as_deref() == Some("INCOMING");
                                
                                let from_did = if is_incoming_role {
                                    req.sender_did.clone()
                                } else {
                                    req.owner_did.clone()
                                };
                                
                                let to_did = if is_incoming_role {
                                    req.owner_did.clone()
                                } else {
                                    req.sender_did.clone()
                                };
                                
                                let date_str = {
                                    let timestamp = js_sys::Date::parse(&req.created_at); // Fixed date parsing for RFC3339
                                    let date = js_sys::Date::new(&timestamp.into());
                                    format!("{}/{}/{}", 
                                        date.get_month() as u32 + 1, 
                                        date.get_date(), 
                                        date.get_full_year())
                                };
                                
                                let status_class = match req.status.to_lowercase().as_str() {
                                    "pending" => "bg-yellow-600/20 text-yellow-400 border-yellow-500/30",
                                    "accepted" => "bg-green-600/20 text-green-400 border-green-500/30",
                                    "refused" => "bg-red-600/20 text-red-400 border-red-500/30",
                                    _ => "bg-slate-600/20 text-slate-400 border-slate-500/30",
                                };

                                let resolve_did_alias = {
                                    let idents = identities.clone();
                                    let pols = policies.clone();
                                    move |did: &str| {
                                        // 1. Check our own identities first
                                        if let Some(matching) = idents.get().iter().find(|i| i.did == did) {
                                            if !matching.alias.is_empty() {
                                                return matching.alias.clone();
                                            }
                                        }
                                        // 2. Check peer contacts
                                        if let Some(matching) = pols.get().iter().find(|p| p.did == did) {
                                            if !matching.alias.is_empty() {
                                                return matching.alias.clone();
                                            }
                                        }
                                        // 3. Fallback: truncated DID
                                        if did.len() > 18 {
                                            format!("{}...{}", &did[..10], &did[did.len()-4..])
                                        } else {
                                            did.to_string()
                                        }
                                    }
                                };

                                let from_alias = resolve_did_alias(&from_did);
                                let to_alias = resolve_did_alias(&to_did);

                                view! {
                                    <div class="bg-slate-900 border border-slate-700/50 rounded-xl p-4 flex flex-col sm:flex-row justify-between gap-4 shadow-sm hover:border-blue-500/30 transition-all group">
                                        <div class="space-y-3 flex-1">
                                            <div class="flex items-center gap-3">
                                                <div class="w-10 h-10 rounded-lg bg-blue-900/30 border border-blue-500/20 flex items-center justify-center shrink-0 text-xl">
                                                    {if is_incoming_role { "📥" } else { "📤" }}
                                                </div>
                                                <div>
                                                    <div class="flex items-center gap-2">
                                                        <span class="font-bold text-white text-base">"Connection Request"</span>
                                                        <span class=format!("px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border {}", status_class)>
                                                            {req.status.to_uppercase()}
                                                        </span>
                                                    </div>
                                                    <div class="text-xs text-slate-400 mt-0.5 flex items-center gap-1">
                                                        <span class="text-slate-500">"Date:"</span> {date_str}
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm bg-slate-800/50 p-3 rounded-lg border border-slate-700/30">
                                                <div>
                                                    <span class="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-1">"Sent by"</span>
                                                    <div class="group relative inline-block">
                                                        <span class="font-bold text-xs text-blue-300 truncate max-w-[180px] block cursor-help border-b border-dashed border-blue-500/30">
                                                            {from_alias}
                                                        </span>
                                                        <div class="invisible group-hover:visible absolute left-0 bottom-full mb-1 p-2 bg-slate-900 border border-slate-700 rounded-lg shadow-xl text-[10px] text-white z-50 whitespace-nowrap font-mono">
                                                            {from_did}
                                                        </div>
                                                    </div>
                                                </div>
                                                <div>
                                                    <span class="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-1">"Sent to"</span>
                                                    <div class="group relative inline-block">
                                                        <span class="font-bold text-xs text-purple-300 truncate max-w-[180px] block cursor-help border-b border-dashed border-purple-500/30">
                                                            {to_alias}
                                                        </span>
                                                        <div class="invisible group-hover:visible absolute left-0 bottom-full mb-1 p-2 bg-slate-900 border border-slate-700 rounded-lg shadow-xl text-[10px] text-white z-50 whitespace-nowrap font-mono">
                                                            {to_did}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="flex sm:flex-col justify-end gap-2 shrink-0">
                                            <Show when=move || is_incoming_role && req.status.to_lowercase() == "pending">
                                                <button 
                                                    on:click={
                                                        let id = id_accept.clone();
                                                        move |_| {
                                                            let ab = base_url.get_value();
                                                            let tt = token.get_value();
                                                            let id = id.clone();
                                                            spawn_local(async move {
                                                                match api::accept_contact_request(&ab, id, tt).await {
                                                                    Ok(_) => {
                                                                        set_success.set(Some("Contact request accepted!".to_string()));
                                                                        set_refresh_trigger.update(|n| *n += 1);
                                                                    },
                                                                    Err(e) => set_error.set(Some(format!("Failed: {}", e))),
                                                                }
                                                            });
                                                        }
                                                    }
                                                    class="flex-1 sm:flex-none bg-green-600/20 text-green-400 px-6 py-2 rounded-lg text-sm font-bold border border-green-500/30 hover:bg-green-500 hover:text-white transition-all text-center shadow-sm">
                                                    "Accept"
                                                </button>
                                                <button 
                                                    on:click={
                                                        let id = id_refuse.clone();
                                                        move |_| {
                                                            let ab = base_url.get_value();
                                                            let tt = token.get_value();
                                                            let id = id.clone();
                                                            spawn_local(async move {
                                                                match api::refuse_contact_request(&ab, id, tt).await {
                                                                    Ok(_) => {
                                                                        set_success.set(Some("Connection request declined.".to_string()));
                                                                        set_refresh_trigger.update(|n| *n += 1);
                                                                    },
                                                                    Err(e) => set_error.set(Some(format!("Failed: {}", e))),
                                                                }
                                                            });
                                                        }
                                                    }
                                                    class="flex-1 sm:flex-none bg-red-600/20 text-red-400 px-6 py-2 rounded-lg text-sm font-bold border border-red-500/30 hover:bg-red-500 hover:text-white transition-all text-center shadow-sm">
                                                    "Decline"
                                                </button>
                                            </Show>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </div>
                </Show>
            </div>
        </div>
    }
}
