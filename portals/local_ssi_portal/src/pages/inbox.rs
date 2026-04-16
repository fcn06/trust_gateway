//! Unified Inbox page — displays messages from all channels natively reading from JetStream.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use std::collections::HashMap;

use crate::api;
use crate::types::{PlainDidcomm, ConnectionPolicy, EnrichedIdentity, SendMessageRequest};

#[component]
pub fn Inbox(
    base_url: String,
    token: String,
    policies: ReadSignal<Vec<ConnectionPolicy>>,
    identities: ReadSignal<Vec<EnrichedIdentity>>,
) -> impl IntoView {
    let (messages, set_messages) = signal(Vec::<PlainDidcomm>::new());
    let (loading, set_loading) = signal(true);
    let (selected_thread, set_selected_thread) = signal(Option::<String>::None);
    let (compose_text, set_compose_text) = signal(String::new());
    let (show_new_msg, set_show_new_msg) = signal(false);
    let (new_recipient, set_new_recipient) = signal(String::new());
    let (sending, set_sending) = signal(false);

    let base_sv = StoredValue::new(base_url.clone());
    let token_sv = StoredValue::new(token.clone());
    let base_clone = base_url.clone();
    let token_clone = token.clone();
    
    let fetch_msgs = {
        let base = base_clone.clone();
        let tok = token_clone.clone();
        move || {
            let b = base.clone();
            let t = tok.clone();
            spawn_local(async move {
                set_loading.set(true);
                if let Ok(msgs) = api::get_messages(&b, t).await {
                    let ui_msgs: Vec<PlainDidcomm> = msgs.into_iter().filter(|m| {
                        if let Some(msg_type) = &m.msg_type {
                            if msg_type.starts_with("https://didcomm.org/invitation/") ||
                               msg_type.starts_with("https://lianxi.io/protocols/contact/") ||
                               msg_type.starts_with("https://didcomm.org/discover-features/") ||
                               msg_type.starts_with("https://didcomm.org/trust-ping/") ||
                               msg_type.starts_with("https://didcomm.org/routing/") {
                                return false;
                            }
                        }
                        true
                    }).collect();
                    set_messages.set(ui_msgs);
                }
                set_loading.set(false);
            });
        }
    };

    // Initial load
    let fm_initial = fetch_msgs.clone();
    Effect::new(move |_| fm_initial());

    let threads = move || {
        let msgs = messages.get();
        let mut groups: HashMap<String, Vec<PlainDidcomm>> = HashMap::new();
        
        for msg in msgs {
            let mut thread_id = "unknown".to_string();
            if let Some(thid) = &msg.thid {
                thread_id = thid.clone();
            } else if let Some(from) = &msg.from {
                thread_id = from.clone();
            }
            groups.entry(thread_id).or_insert_with(Vec::new).push(msg);
        }
        
        let mut sorted_groups: Vec<(String, Vec<PlainDidcomm>)> = groups.into_iter().collect();
        sorted_groups.sort_by(|a, b| {
            let a_max = a.1.iter().filter_map(|m| m.created_time).max().unwrap_or(0);
            let b_max = b.1.iter().filter_map(|m| m.created_time).max().unwrap_or(0);
            b_max.cmp(&a_max)
        });
        
        for (_, group_msgs) in sorted_groups.iter_mut() {
            group_msgs.sort_by_key(|m| m.created_time.unwrap_or(0));
        }
        sorted_groups
    };

    // Send reply handler — uses StoredValue so it's Fn-compatible
    let do_send_reply = move || {
        if let Some(tid) = selected_thread.get() {
            let text = compose_text.get();
            if text.is_empty() { return; }
            
            // Resolve recipient and thread ID
            let msgs = messages.get();
            let my_dids: Vec<String> = identities.get().into_iter().map(|id| id.did).collect();
            
            let thread_msgs: Vec<&PlainDidcomm> = msgs.iter().filter(|m| {
                m.thid.as_ref() == Some(&tid) || (m.thid.is_none() && m.from.as_ref() == Some(&tid))
            }).collect();
            
            // Recipient is the first "other" DID we find in the thread. 
            // If all messages are from us, the recipient is ourselves.
            let recipient_did = thread_msgs.iter()
                .find_map(|m| {
                    m.from.as_ref().filter(|f| !my_dids.contains(f))
                })
                .cloned()
                .unwrap_or_else(|| {
                    // Fallback: use 'to' from first message if from is self, or just the tid if it looks like a DID
                    thread_msgs.first()
                        .and_then(|m| m.to.as_ref()?.first().cloned())
                        .unwrap_or(tid.clone())
                });

            let b = base_sv.get_value();
            let t = token_sv.get_value();
            let req = SendMessageRequest {
                to: recipient_did,
                body: text,
                r#type: "https://didcomm.org/message/2.0/chat".to_string(),
                thid: Some(tid),
            };
            let b2 = base_sv.get_value();
            let t2 = token_sv.get_value();
            spawn_local(async move {
                set_sending.set(true);
                if let Ok(_) = api::send_message(&b, req, t).await {
                    set_compose_text.set(String::new());
                    // Refresh messages
                    if let Ok(msgs) = api::get_messages(&b2, t2).await {
                        let ui_msgs: Vec<PlainDidcomm> = msgs.into_iter().filter(|m| {
                            if let Some(msg_type) = &m.msg_type {
                                if msg_type.starts_with("https://didcomm.org/invitation/") ||
                                   msg_type.starts_with("https://lianxi.io/protocols/contact/") ||
                                   msg_type.starts_with("https://didcomm.org/discover-features/") ||
                                   msg_type.starts_with("https://didcomm.org/trust-ping/") ||
                                   msg_type.starts_with("https://didcomm.org/routing/") {
                                    return false;
                                }
                            }
                            true
                        }).collect();
                        set_messages.set(ui_msgs);
                    }
                }
                set_sending.set(false);
            });
        }
    };

    // Send new message handler
    let do_send_new = move || {
        let rec = new_recipient.get();
        let text = compose_text.get();
        if !rec.is_empty() && !text.is_empty() {
            let b = base_sv.get_value();
            let t = token_sv.get_value();
            let b2 = base_sv.get_value();
            let t2 = token_sv.get_value();
            let req = SendMessageRequest {
                to: rec.clone(),
                body: text,
                r#type: "https://didcomm.org/message/2.0/chat".to_string(),
                thid: None,
            };
            spawn_local(async move {
                set_sending.set(true);
                if let Ok(_) = api::send_message(&b, req, t).await {
                    set_compose_text.set(String::new());
                    set_show_new_msg.set(false);
                    set_selected_thread.set(Some(rec));
                    if let Ok(msgs) = api::get_messages(&b2, t2).await {
                        let ui_msgs: Vec<PlainDidcomm> = msgs.into_iter().filter(|m| {
                            if let Some(msg_type) = &m.msg_type {
                                if msg_type.starts_with("https://didcomm.org/invitation/") ||
                                   msg_type.starts_with("https://lianxi.io/protocols/contact/") ||
                                   msg_type.starts_with("https://didcomm.org/discover-features/") ||
                                   msg_type.starts_with("https://didcomm.org/trust-ping/") ||
                                   msg_type.starts_with("https://didcomm.org/routing/") {
                                    return false;
                                }
                            }
                            true
                        }).collect();
                        set_messages.set(ui_msgs);
                    }
                }
                set_sending.set(false);
            });
        }
    };

    view! {
        <div class="h-full flex flex-col space-y-4">
            <div class="flex flex-wrap items-center justify-between gap-2 px-2">
                <h1 class="text-xl md:text-2xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                    "📥 Unified Inbox"
                </h1>
                <div class="flex flex-wrap gap-2">
                    <button
                        on:click={
                            let fm = fetch_msgs.clone();
                            move |_| fm()
                        }
                        class="bg-slate-700 hover:bg-slate-600 text-white px-3 py-2 rounded-lg text-sm font-medium shadow-sm border border-slate-600 transition-colors flex items-center gap-2"
                    >
                        "Refresh"
                    </button>
                    <button 
                        on:click=move |_| {
                            set_show_new_msg.set(true);
                            set_selected_thread.set(None);
                            set_new_recipient.set(String::new());
                            set_compose_text.set(String::new());
                        }
                        class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-sm font-bold shadow-lg shadow-blue-500/20 transition-all flex items-center gap-2"
                    >
                        <span class="text-lg">"+"</span> "New"
                    </button>
                </div>
            </div>

            <Show when=move || loading.get() && messages.get().is_empty()>
                <div class="flex items-center justify-center py-12">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400 border-t-transparent"></div>
                </div>
            </Show>

            <Show when=move || !loading.get() || !messages.get().is_empty()>
                <div class="flex-1 flex gap-0 md:gap-4 overflow-hidden h-full pb-6">
                    // Left Pane: Thread List — full-width on mobile, hidden when a thread is selected
                    <div class=move || format!(
                        "md:w-1/3 bg-slate-800 rounded-xl border border-slate-700 overflow-y-auto flex flex-col select-none shadow-xl {}",
                        if (selected_thread.get().is_some() || show_new_msg.get()) { "hidden md:flex w-0 md:w-1/3" } else { "flex w-full md:w-1/3" }
                    )>
                        {move || {
                            let curr_threads = threads();
                            if curr_threads.is_empty() {
                                view! {
                                    <div class="p-8 text-center text-slate-500 italic mt-10">
                                        "No conversations yet."
                                    </div>
                                }.into_any()
                            } else {
                                curr_threads.into_iter().map(|(tid, msgs)| {
                                    let tid_clone = tid.clone();
                                    let latest = msgs.last().unwrap();
                                    
                                    // Resolve the other party for display
                                    let my_dids: Vec<String> = identities.get().into_iter().map(|i| i.did).collect();

                                    // Check if this is a self-message: first message's "from" AND "to" are both our own DIDs
                                    let first_msg = msgs.first();
                                    let first_from_is_self = first_msg
                                        .and_then(|m| m.from.as_ref())
                                        .map(|f| my_dids.contains(f))
                                        .unwrap_or(false);
                                    let first_to_is_self = first_msg
                                        .and_then(|m| m.to.as_ref())
                                        .map(|tos| tos.iter().all(|t| my_dids.contains(t)))
                                        .unwrap_or(false);
                                    let is_self_message = first_from_is_self && first_to_is_self;

                                    let origin_did = first_msg.and_then(|m| m.from.clone()).unwrap_or_default();
                                    
                                    let display_name = if is_self_message {
                                        "Myself".to_string()
                                    } else {
                                        if let Some(identity) = identities.get().iter().find(|i| i.did == origin_did) {
                                            identity.alias.clone()
                                        } else if let Some(policy) = policies.get().iter().find(|p| p.did == origin_did) {
                                            policy.alias.clone()
                                        } else {
                                            if origin_did.len() > 16 { format!("{}...{}", &origin_did[..8], &origin_did[origin_did.len()-4..]) } else if !origin_did.is_empty() { origin_did.clone() } else { "Unknown".to_string() }
                                        }
                                    };

                                    let preview = match &latest.body {
                                        serde_json::Value::String(s) => s.clone(),
                                        val => val.to_string(),
                                    };
                                    
                                    let is_selected = selected_thread.get() == Some(tid.clone()) && !show_new_msg.get();
                                    let bg_class = if is_selected { "bg-slate-700/80 border-l-4 border-l-blue-400" } else { "hover:bg-slate-750 border-l-4 border-l-transparent" };

                                    view! {
                                        <div 
                                            class=format!("p-4 border-b border-slate-700/50 cursor-pointer transition-colors block {}", bg_class)
                                            on:click=move |_| {
                                                set_selected_thread.set(Some(tid_clone.clone()));
                                                set_show_new_msg.set(false);
                                            }
                                        >
                                            <div class="flex justify-between items-start mb-1">
                                                <span class="font-bold text-slate-200 truncate pr-2">{display_name}</span>
                                                <span class="text-[10px] text-slate-500 font-mono flex-shrink-0">
                                                    {format_timestamp(latest.created_time.unwrap_or(0))}
                                                </span>
                                            </div>
                                            <div class="text-[10px] text-slate-500 font-mono truncate mb-1" title="Thread ID">
                                                {format!("thid: {}", tid_clone.clone())}
                                            </div>
                                            <div class="text-xs text-slate-400 truncate pr-2">
                                                {preview}
                                            </div>
                                        </div>
                                    }
                                }).collect_view().into_any()
                            }
                        }}
                    </div>

                    // Right Pane: Active Thread or New Message — full-width on mobile
                    <div class=move || format!(
                        "bg-slate-900 rounded-xl border border-slate-700 flex flex-col overflow-hidden relative shadow-inner {}",
                        if (selected_thread.get().is_some() || show_new_msg.get()) { "flex w-full md:w-2/3" } else { "hidden md:flex w-0 md:w-2/3" }
                    )>
                        <Show when=move || show_new_msg.get()>
                            <div class="flex-1 flex flex-col p-4 md:p-6 space-y-6">
                                <h2 class="text-xl font-bold text-white mb-2">"New Message"</h2>
                                <div class="space-y-4">
                                    <div>
                                        <label class="block text-sm font-medium text-slate-400 mb-1">"To:"</label>
                                        <select
                                            class="w-full bg-slate-800 border border-slate-600 rounded-lg p-3 text-sm text-white focus:ring-2 focus:ring-blue-500 outline-none"
                                            on:change=move |ev| set_new_recipient.set(event_target_value(&ev))
                                        >
                                            <option value="">"Select a recipient..."</option>
                                            <optgroup label="Self">
                                                {move || identities.get().into_iter().map(|id| {
                                                    let d = id.did.clone();
                                                    let alias = id.alias.clone();
                                                    view! { <option value=d>{alias}</option> }
                                                }).collect_view()}
                                            </optgroup>
                                            <optgroup label="Contacts">
                                                {move || policies.get().into_iter().filter(|p| !p.alias.is_empty()).map(|p| {
                                                    let d = p.did.clone();
                                                    let alias = p.alias.clone();
                                                    view! { <option value=d>{alias}</option> }
                                                }).collect_view()}
                                            </optgroup>
                                        </select>
                                    </div>
                                    <div class="flex-1">
                                        <label class="block text-sm font-medium text-slate-400 mb-1">"Message:"</label>
                                        <textarea
                                            class="w-full h-48 bg-slate-800 border border-slate-600 rounded-lg p-3 text-sm text-white focus:ring-2 focus:ring-blue-500 outline-none resize-none"
                                            placeholder="Type your message here..."
                                            prop:value=move || compose_text.get()
                                            on:input=move |ev| set_compose_text.set(event_target_value(&ev))
                                        ></textarea>
                                    </div>
                                    <div class="flex justify-end gap-3">
                                        <button 
                                            on:click=move |_| set_show_new_msg.set(false)
                                            class="px-4 py-2 rounded-lg text-slate-300 hover:bg-slate-800 transition-colors font-medium text-sm">
                                            "Cancel"
                                        </button>
                                        <button 
                                            on:click=move |_| do_send_new()
                                            disabled=move || new_recipient.get().is_empty() || compose_text.get().is_empty() || sending.get()
                                            class="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-bold shadow-lg shadow-blue-500/20 transition-all text-sm">
                                            {move || if sending.get() { "Sending..." } else { "Send Message" }}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </Show>

                        <Show when=move || !show_new_msg.get() && selected_thread.get().is_some()>
                            {move || {
                                let curr_tid = selected_thread.get().unwrap();
                                let curr_threads = threads();
                                let thread_msgs = curr_threads.into_iter().find(|(t, _)| t == &curr_tid).map(|(_, m)| m).unwrap_or_default();
                                
                                let my_dids: Vec<String> = identities.get().into_iter().map(|i| i.did).collect();

                                // Resolve the other party for the header
                                let first_thread_msg = thread_msgs.first();
                                let origin_did_for_header = first_thread_msg.and_then(|m| m.from.clone()).unwrap_or_default();
                                
                                let header_name = if let Some(identity) = identities.get().iter().find(|i| i.did == origin_did_for_header) {
                                    identity.alias.clone()
                                } else if let Some(policy) = policies.get().iter().find(|p| p.did == origin_did_for_header) {
                                    policy.alias.clone()
                                } else {
                                    if origin_did_for_header.len() > 16 { format!("{}...{}", &origin_did_for_header[..8], &origin_did_for_header[origin_did_for_header.len()-4..]) } else if !origin_did_for_header.is_empty() { origin_did_for_header.clone() } else { "Unknown".to_string() }
                                };

                                view! {
                                    <div class="flex-1 overflow-y-scroll p-4 space-y-6 flex flex-col">
                                        <div class="flex-1 space-y-4 pr-2">
                                            // Mobile back button + thread header
                                            <div class="flex items-center gap-3 pb-4 border-b border-slate-800">
                                                <button
                                                    on:click=move |_| set_selected_thread.set(None)
                                                    class="md:hidden flex items-center gap-1 text-slate-400 hover:text-white transition-colors px-2 py-1 rounded-lg hover:bg-slate-800"
                                                >
                                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
                                                    </svg>
                                                    "Back"
                                                </button>
                                                <span class="text-xs text-slate-500 font-mono bg-slate-800 px-3 py-1 rounded-full">{header_name}</span>
                                            </div>
                                            {thread_msgs.into_iter().map(|msg| {
                                                let is_outbound = my_dids.contains(&msg.from.clone().unwrap_or_default());
                                                let align_class = if is_outbound { "justify-end" } else { "justify-start" };
                                                let bubble_class = if is_outbound { 
                                                    "bg-blue-600 text-white rounded-l-2xl rounded-tr-2xl" 
                                                } else { 
                                                    "bg-slate-700 text-slate-200 rounded-r-2xl rounded-tl-2xl" 
                                                };
                                                
                                                let mut text_to_parse = match &msg.body {
                                                    serde_json::Value::String(s) => s.clone(),
                                                    serde_json::Value::Object(obj) => {
                                                        if let Some(content) = obj.get("content").and_then(|c| c.as_str()) {
                                                            content.to_string()
                                                        } else {
                                                            serde_json::to_string_pretty(&msg.body).unwrap_or_default()
                                                        }
                                                    },
                                                    val => serde_json::to_string_pretty(val).unwrap_or_default(),
                                                };
                                                
                                                // Handle escaped format returned by serde_json::to_string_pretty if it was a nested JSON string
                                                if text_to_parse.starts_with('"') && text_to_parse.ends_with('"') {
                                                    if let Ok(unquoted) = serde_json::from_str::<String>(&text_to_parse) {
                                                        text_to_parse = unquoted;
                                                    }
                                                }
                                                
                                                let mut html_output = String::new();
                                                let parser = pulldown_cmark::Parser::new(&text_to_parse);
                                                pulldown_cmark::html::push_html(&mut html_output, parser);
    
                                                view! {
                                                    <div class=format!("flex {}", align_class)>
                                                        <div class="max-w-[80%] flex flex-col">
                                                            <div class=format!("flex items-baseline gap-2 mb-1 px-1 {}", if is_outbound { "justify-end" } else { "" })>
                                                                <span class="text-[10px] text-slate-400 font-medium">
                                                                    {if is_outbound { "You".to_string() } else {
                                                                        msg.alias.clone().or_else(|| {
                                                                            msg.from.as_ref().and_then(|f| policies.get().iter().find(|p| p.did == *f).map(|p| p.alias.clone()))
                                                                        }).unwrap_or_else(|| "Contact".to_string())
                                                                    }}
                                                                </span>
                                                                <span class="text-[9px] text-slate-600 font-mono">{format_timestamp(msg.created_time.unwrap_or(0))}</span>
                                                            </div>
                                                            <div class=format!("p-3 shadow-md {} space-y-2 [&>p]:mb-2 [&>h1]:text-lg [&>h1]:font-bold [&>ul]:list-disc [&>ul]:ml-4 [&>ol]:list-decimal [&>ol]:ml-4 [&>pre]:bg-slate-900/50 [&>pre]:p-2 [&>pre]:rounded-md [&>code]:bg-slate-900/50 [&>code]:px-1 [&>code]:rounded-sm [&>a]:text-blue-300 [&>a]:underline", bubble_class) inner_html=html_output>
                                                            </div>
                                                        </div>
                                                    </div>
                                                }
                                            }).collect_view()}
                                        </div>
                                    </div>
                                    
                                    // Chat Composer Bar — sticky bottom for mobile keyboard
                                    <div class="sticky bottom-0 p-3 md:p-4 pr-20 md:pr-24 bg-slate-800/80 backdrop-blur-sm border-t border-slate-700">
                                        <div class="flex items-end gap-2">
                                            <textarea
                                                class="flex-1 bg-slate-900 border border-slate-600 rounded-lg p-3 text-sm text-white focus:ring-2 focus:ring-blue-500 outline-none resize-none min-h-[44px] max-h-32"
                                                placeholder="Type a reply..."
                                                rows="1"
                                                prop:value=move || compose_text.get()
                                                on:input=move |ev| set_compose_text.set(event_target_value(&ev))
                                            ></textarea>
                                            <button 
                                                on:click=move |_| do_send_reply()
                                                disabled=move || compose_text.get().is_empty() || sending.get()
                                                class="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg p-3 shadow-lg shadow-blue-500/20 transition-all flex-shrink-0"
                                            >
                                                <svg class="w-5 h-5 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg>
                                            </button>
                                        </div>
                                    </div>
                                }
                            }}
                        </Show>
                        
                        <Show when=move || !show_new_msg.get() && selected_thread.get().is_none()>
                            <div class="flex-1 flex flex-col items-center justify-center text-slate-500 p-8 text-center">
                                <div class="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mb-4">
                                    <svg class="w-10 h-10 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path></svg>
                                </div>
                                <h3 class="text-lg font-medium text-slate-300">"Your Messages"</h3>
                                <p class="text-sm mt-2 max-w-sm">"Select a conversation from the left to view the thread, or create a new message to start a chat."</p>
                            </div>
                        </Show>
                    </div>
                </div>
            </Show>
        </div>
    }
}

fn format_timestamp(ts: i64) -> String {
    let now = js_sys::Date::now() as i64 / 1000;
    let diff = now - ts;
    if diff < 60 { "just now".to_string() }
    else if diff < 3600 { format!("{}m ago", diff / 60) }
    else if diff < 86400 { format!("{}h ago", diff / 3600) }
    else { format!("{}d ago", diff / 86400) }
}
