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
        <div class="space-y-6 text-white max-w-4xl mx-auto">
            <h2 class="text-2xl font-bold">"Contact Requests"</h2>
            
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
                <div class="flex justify-between items-center mb-2 border-b border-slate-700 pb-2">
                    <h3 class="text-lg font-semibold">"Send Contact Request"</h3>
                    <div class="flex gap-2 bg-slate-900 p-1 rounded-lg">
                        <button 
                            on:click=move |_| set_is_offline.set(false)
                            class=move || format!("px-3 py-1 rounded text-xs font-bold transition-all {}", 
                                if !is_offline.get() { "bg-blue-600/30 text-blue-400" } else { "text-slate-500 hover:text-slate-300" })
                        >
                            "Public Ledger"
                        </button>
                        <button 
                            on:click=move |_| set_is_offline.set(true)
                            class=move || format!("px-3 py-1 rounded text-xs font-bold transition-all {}", 
                                if is_offline.get() { "bg-purple-600/30 text-purple-400" } else { "text-slate-500 hover:text-slate-300" })
                        >
                            "Ledgerless Connection"
                        </button>
                    </div>
                </div>
                <Show 
                    when=move || is_offline.get()
                    fallback=move || view! {
                        <div class="space-y-4">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <input 
                                    type="text" 
                                    placeholder="Contact Identity (e.g. username@domain or identifier)"
                                    prop:value=move || target_did.get()
                                    on:input=move |e| set_target_did.set(event_target_value(&e))
                                    class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none w-full"
                                />
                                <input 
                                    type="text" 
                                    placeholder="Message (e.g. Hi, let's connect!)"
                                    prop:value=move || msg_body.get()
                                    on:input=move |e| set_msg_body.set(event_target_value(&e))
                                    class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none w-full"
                                />
                            </div>
                            <button 
                                on:click=on_send_request
                                disabled=move || is_sending.get()
                                class="bg-blue-600 hover:bg-blue-500 px-6 py-2 rounded-lg font-bold transition-all disabled:opacity-50"
                            >
                                {move || if is_sending.get() { "Sending..." } else { "Send Request" }}
                            </button>
                        </div>
                    }
                >
                    <div class="space-y-4">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <input 
                                type="text" 
                                placeholder="Public Contact Identity (e.g. example.com or identifier)"
                                prop:value=move || target_did.get()
                                on:input=move |e| set_target_did.set(event_target_value(&e))
                                class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-purple-500 outline-none w-full"
                            />
                            <input 
                                type="text" 
                                placeholder="Initial Message (Optional)"
                                prop:value=move || msg_body.get()
                                on:input=move |e| set_msg_body.set(event_target_value(&e))
                                class="bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-purple-500 outline-none w-full"
                            />
                        </div>
                        <button 
                            on:click=on_send_request
                            disabled=move || is_sending.get()
                            class="bg-purple-600 hover:bg-purple-500 px-6 py-2 rounded-lg font-bold transition-all disabled:opacity-50"
                        >
                            {move || if is_sending.get() { "Sending..." } else { "Send Secure Request" }}
                        </button>
                    </div>
                </Show>
            </div>

            // Pending Requests List
            <div class="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden shadow-2xl">
                <div class="p-4 border-b border-slate-700 flex justify-between items-center">
                    <h3 class="text-lg font-semibold">"Pending Requests"</h3>
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
                            "No pending requests."
                        </div>
                    }
                >
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-900 text-slate-400 uppercase text-xs">
                                <tr>
                                    <th class="p-4">"From"</th>
                                    <th class="p-4">"To"</th>
                                    <th class="p-4">"Status"</th>
                                    <th class="p-4">"Date"</th>
                                    <th class="p-4 text-right">"Actions"</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-700">
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

                                        view! {
                                            <tr>
                                                <td class="p-4">
                                                    <div class="flex flex-col">
                                                        <span class="font-bold text-blue-300">"Request"</span>
                                                        <span class="text-[10px] text-slate-500 font-mono truncate max-w-32 group relative cursor-help">
                                                            "View Details"
                                                            <div class="invisible group-hover:visible absolute left-0 bottom-full mb-1 p-2 bg-slate-800 border border-slate-600 rounded shadow-xl text-xs z-50 whitespace-nowrap">
                                                                {from_did}
                                                            </div>
                                                        </span>
                                                    </div>
                                                </td>
                                                <td class="p-4">
                                                    <span class="text-[10px] text-slate-400 font-mono truncate max-w-32 group relative cursor-help">
                                                        "View Details"
                                                        <div class="invisible group-hover:visible absolute left-0 bottom-full mb-1 p-2 bg-slate-800 border border-slate-600 rounded shadow-xl text-xs z-50 whitespace-nowrap">
                                                            {to_did}
                                                        </div>
                                                    </span>
                                                </td>
                                                <td class="p-4">
                                                    <span class=format!("px-2 py-1 rounded-full border text-[10px] font-bold {}", status_class)>
                                                        {req.status.to_uppercase()}
                                                    </span>
                                                </td>
                                                <td class="p-4 text-slate-400 text-xs">{date_str}</td>
                                                <td class="p-4">
                                                    <Show when=move || is_incoming_role && req.status.to_lowercase() == "pending">
                                                        <div class="flex gap-2 justify-end">
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
                                                                class="bg-green-600/20 text-green-400 px-3 py-1 rounded text-xs font-bold border border-green-500/30 hover:bg-green-600/40 transition-all">
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
                                                                                    set_success.set(Some("Contact request refused.".to_string()));
                                                                                    set_refresh_trigger.update(|n| *n += 1);
                                                                                },
                                                                                Err(e) => set_error.set(Some(format!("Failed: {}", e))),
                                                                            }
                                                                        });
                                                                    }
                                                                }
                                                                class="bg-red-600/20 text-red-400 px-3 py-1 rounded text-xs font-bold border border-red-500/30 hover:bg-red-600/40 transition-all">
                                                                "Refuse"
                                                            </button>
                                                        </div>
                                                    </Show>
                                                </td>
                                            </tr>
                                        }
                                    }
                                />
                            </tbody>
                        </table>
                    </div>
                </Show>
            </div>
        </div>
    }
}
