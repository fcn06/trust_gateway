//! Messaging page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::{PlainDidcomm, ConnectionPolicy, EnrichedIdentity, SendMessageRequest};

#[component]
pub fn Messaging(
    base_url: String, 
    username: String, 
    token: String, 
    policies: ReadSignal<Vec<ConnectionPolicy>>, 
    identities: ReadSignal<Vec<EnrichedIdentity>>, 
    initial_msg: String
) -> impl IntoView {
    let (recipient_input, set_recipient) = signal(String::new());
    let (msg_input, set_msg) = signal(initial_msg);
    let (messages, set_messages) = signal(Vec::<PlainDidcomm>::new());
    let (send_status, set_send_status) = signal(Option::<(String, bool)>::None);
    
    let base_url = store_value(base_url);
    let token = store_value(token);
    
    let fetch_msgs = {
        let fm = set_messages;
        let ab = base_url;
        let tok = token;
        move || {
            let ab_val = ab.get_value();
            let tok_val = tok.get_value();
            spawn_local(async move {
                if let Ok(msgs) = api::get_messages(&ab_val, tok_val).await {
                    fm.set(msgs);
                }
            });
        }
    };
    
    let fm_for_effect = fetch_msgs.clone();
    Effect::new(move |_| fm_for_effect());

    let on_send = {
        let fm = fetch_msgs.clone();
        move |_| {
            let r = recipient_input.get();
            let m = msg_input.get();
            if r.is_empty() || m.is_empty() { return; }
            
            set_send_status.set(None);
            
            let req = SendMessageRequest {
                to: r,
                body: m,
                r#type: "https://didcomm.org/message/2.0/chat".to_string(),
                thid: None,
            };
            
            let tt = token.get_value();
            let ab = base_url.get_value();
            spawn_local(async move {
                match api::send_message(&ab, req, tt).await {
                    Ok(_) => { 
                        set_send_status.set(Some(("✅ Message sent successfully!".to_string(), true)));
                        set_msg.set(String::new());
                        fm();
                    },
                    Err(e) => set_send_status.set(Some((format!("❌ Send failed: {}", e), false))),
                }
            });
        }
    };

    view! {
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 text-white h-[calc(100vh-140px)]">
            <div class="md:col-span-2 bg-slate-800 rounded-2xl border border-slate-700 shadow-xl flex flex-col overflow-hidden">
                <div class="p-4 border-b border-slate-700 font-bold">"Messages"</div>
                <div class="flex-1 overflow-auto p-4 space-y-4">
                    <For
                        each=move || messages.get()
                        key=|m| m.id.clone()
                        children=move |m| {
                            let date_str = m.created_time.map(|ts| {
                                let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((ts * 1000) as f64));
                                format!("{}/{}/{} {}:{:02}", 
                                    date.get_month() as u32 + 1, 
                                    date.get_date(), 
                                    date.get_full_year(),
                                    date.get_hours(),
                                    date.get_minutes())
                            }).unwrap_or_else(|| "Unknown date".to_string());

                            let status = m.status.clone().unwrap_or_else(|| "distributed".to_string());
                            let status_class = if status == "rejected" {
                                "bg-red-600/20 text-red-400 border-red-500/30"
                            } else {
                                "bg-green-600/20 text-green-400 border-green-500/30"
                            };

                            let my_dids = identities.get();
                            let from_did = m.from.as_deref().unwrap_or_default();
                            let is_sent = my_dids.iter().any(|i| i.did == from_did);
                            
                            let (label, display_did) = if is_sent {
                                ("To: ", m.to.as_ref().and_then(|t| t.get(0)).cloned().unwrap_or_else(|| "Unknown".to_string()))
                            } else {
                                ("From: ", from_did.to_string())
                            };

                            let display_name = if let Some(alias) = &m.alias {
                                alias.clone()
                            } else {
                                policies.get().iter()
                                    .find(|p| p.did == display_did)
                                    .map(|p| if p.alias.is_empty() { display_did.clone() } else { p.alias.clone() })
                                    .unwrap_or(display_did)
                            };

                            let msg_type_label = m.msg_type.as_deref()
                                .unwrap_or("unknown")
                                .split('/')
                                .last()
                                .unwrap_or("unknown")
                                .to_string();

                            view! {
                                <div class="bg-slate-900 p-3 rounded-lg border border-slate-700">
                                    <div class="flex justify-between text-xs text-slate-500 mb-1">
                                        <div class="flex gap-2 items-center">
                                            <span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono border border-slate-700 uppercase">{msg_type_label}</span>
                                            <span>{label} {display_name}</span>
                                        </div>
                                        <div class="flex items-center gap-2">
                                            <span class=format!("px-2 py-0.5 rounded-full border text-[10px] font-bold {}", status_class)>
                                                {status.to_uppercase()}
                                            </span>
                                            <span>{date_str}</span>
                                        </div>
                                    </div>
                                    <div class="text-sm">{m.body.as_str().unwrap_or(&m.body.to_string()).to_string()}</div>
                                </div>
                            }
                        }
                    />
                    <Show when=move || messages.get().is_empty()>
                         <div class="text-slate-500">"No messages"</div>
                    </Show>
                </div>
            </div>
            <div class="space-y-6 overflow-auto">
                <div class="bg-slate-800 rounded-2xl border border-slate-700 shadow-xl p-6 space-y-4 h-fit">
                    <h3 class="font-bold">"Send Message"</h3>
                    <input 
                        type="text" 
                        placeholder="Recipient DID" 
                        class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm"
                        prop:value=move || recipient_input.get()
                        on:input=move |ev| set_recipient.set(event_target_value(&ev))
                    />
                    <textarea 
                        placeholder="Message" 
                        class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm h-32"
                        prop:value=move || msg_input.get()
                        on:input=move |ev| set_msg.set(event_target_value(&ev))
                    ></textarea>
                    <button 
                        on:click=on_send
                        class="w-full bg-blue-600 hover:bg-blue-500 py-2 rounded font-bold shadow-lg shadow-blue-600/20">
                        "Send"
                    </button>
                    
                    <Show when=move || send_status.get().is_some()>
                        {move || {
                            let (msg, is_success) = send_status.get().unwrap_or_default();
                            let class = if is_success {
                                "mt-2 p-2 rounded bg-green-900/30 border border-green-500/50 text-green-400 text-xs"
                            } else {
                                "mt-2 p-2 rounded bg-red-900/30 border border-red-500/50 text-red-400 text-xs"
                            };
                            view! { <div class=class>{msg}</div> }
                        }}
                    </Show>
                </div>

                <div class="bg-slate-800 rounded-2xl border border-slate-700 shadow-xl p-6 space-y-4 h-fit">
                    <h3 class="font-bold text-blue-400">"Quick Contacts"</h3>
                    <div class="space-y-2 max-h-64 overflow-auto pr-2 custom-scrollbar">
                        <For
                            each={move || policies.get().into_iter().filter(|p| !p.alias.is_empty()).collect::<Vec<_>>()}
                            key=|p| p.did.clone()
                            children=move |p| {
                                let d = p.did.clone();
                                view! {
                                    <div class="flex justify-between items-center bg-slate-900/50 p-2.5 rounded-xl border border-slate-700/50 hover:border-blue-500/30 transition-all group">
                                        <div class="flex flex-col min-w-0">
                                            <span class="text-sm font-bold text-slate-200 group-hover:text-blue-300 transition-colors">{p.alias.clone()}</span>
                                            <span class="text-[10px] text-slate-500 truncate w-32 font-mono">{p.did.clone()}</span>
                                        </div>
                                        <button 
                                            on:click=move |_| set_recipient.set(d.clone())
                                            class="bg-blue-600/10 hover:bg-blue-600 text-blue-400 hover:text-white px-3 py-1 rounded-lg text-xs font-bold border border-blue-500/20 hover:border-blue-500 transition-all shadow-sm">
                                            "Msg"
                                        </button>
                                    </div>
                                }
                            }
                        />
                        <Show when={move || policies.get().iter().all(|p| p.alias.is_empty())}>
                            <div class="text-xs text-slate-500 italic text-center py-4 bg-slate-900/20 rounded-xl border border-dashed border-slate-700">
                                "No aliases defined in Approved Contacts"
                            </div>
                        </Show>
                    </div>
                </div>
            </div>
        </div>
    }
}
