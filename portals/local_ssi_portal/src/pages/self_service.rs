//! Self Service page component for personal notes and sharing.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::SendMessageRequest;

#[component]
pub fn SelfService(base_url: String, token: String, initial_msg: String) -> impl IntoView {
    let initial_topic = detect_topic(&initial_msg);
    let (selected_topic, set_selected_topic) = signal(initial_topic);
    let (note_content, set_note_content) = signal(initial_msg);
    let (note_status, set_note_status) = signal(Option::<(String, bool)>::None);
    let (is_note_loading, set_note_loading) = signal(false);



    let base_url = store_value(base_url);
    let token = store_value(token);

    let on_save_note = move |_| {
        let content = note_content.get();
        if content.is_empty() {
            set_note_status.set(Some(("Please enter a note".to_string(), false)));
            return;
        }
        
        let topic = selected_topic.get();
        
        set_note_loading.set(true);
        set_note_status.set(None);
        
        let ab = base_url.get_value();
        let tt = token.get_value();
        
        spawn_local(async move {
            match api::get_active_did(&ab, tt.clone()).await {
                Ok(my_did) => {
                    let thid = if topic.is_empty() { None } else { Some(topic) };
                    let req = SendMessageRequest {
                        to: my_did,
                        body: content,
                        r#type: "https://didcomm.org/self-note/1.0/note".to_string(),
                        thid,
                    };
                    
                    match api::send_message(&ab, req, tt).await {
                        Ok(_) => {
                            set_note_status.set(Some(("✅ Note saved to your personal vault!".to_string(), true)));
                            set_note_content.set(String::new());
                            set_selected_topic.set(String::new());
                        },
                        Err(e) => set_note_status.set(Some((format!("❌ Failed: {}", e), false))),
                    }
                },
                Err(e) => set_note_status.set(Some((format!("❌ No active identity: {}", e), false))),
            }
            set_note_loading.set(false);
        });
    };

    let on_ask_agent = move |_| {
        let mut content = note_content.get();
        if content.is_empty() {
            set_note_status.set(Some(("Please enter a note".to_string(), false)));
            return;
        }
        
        if !content.starts_with("@agent") {
            content = format!("@agent {}", content);
        }
        
        let topic = selected_topic.get();
        
        set_note_loading.set(true);
        set_note_status.set(None);
        
        let ab = base_url.get_value();
        let tt = token.get_value();
        
        spawn_local(async move {
            match api::get_active_did(&ab, tt.clone()).await {
                Ok(my_did) => {
                    let thid = if topic.is_empty() { None } else { Some(topic) };
                    let req = SendMessageRequest {
                        to: my_did,
                        body: content,
                        r#type: "https://didcomm.org/self-note/1.0/note".to_string(),
                        thid,
                    };
                    
                    match api::send_message(&ab, req, tt).await {
                        Ok(_) => {
                            set_note_status.set(Some(("✅ Message sent to personal agent!".to_string(), true)));
                            set_note_content.set(String::new());
                            set_selected_topic.set(String::new());
                        },
                        Err(e) => set_note_status.set(Some((format!("❌ Failed: {}", e), false))),
                    }
                },
                Err(e) => set_note_status.set(Some((format!("❌ No active identity: {}", e), false))),
            }
            set_note_loading.set(false);
        });
    };



    view! {
        <div class="space-y-6 text-white max-w-2xl mx-auto">
            <h2 class="text-2xl font-bold">"Self Service"</h2>
            <p class="text-slate-400">"Send notes and content to yourself. Perfect for capturing shared content or personal reminders."</p>
            
            <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl space-y-4">
                <div>
                    <label class="block text-xs font-bold text-slate-400 mb-2 uppercase">"Topic (Optional)"</label>
                    <div class="flex flex-wrap gap-2 mb-2">
                        <button 
                            type="button"
                            on:click=move |_| {
                                if selected_topic.get() == "Links" {
                                    set_selected_topic.set(String::new());
                                } else {
                                    set_selected_topic.set("Links".to_string());
                                }
                            }
                            class=move || {
                                let active = selected_topic.get() == "Links";
                                format!(
                                    "px-3 py-1.5 rounded-full text-xs font-bold transition-all border {}",
                                    if active { "bg-blue-600 border-blue-500 text-white shadow-md shadow-blue-600/20" } else { "bg-slate-900 border-slate-700 text-slate-400 hover:text-white" }
                                )
                            }
                        >
                            "📎 Links"
                        </button>
                        <button 
                            type="button"
                            on:click=move |_| {
                                if selected_topic.get() == "Tasks" {
                                    set_selected_topic.set(String::new());
                                } else {
                                    set_selected_topic.set("Tasks".to_string());
                                }
                            }
                            class=move || {
                                let active = selected_topic.get() == "Tasks";
                                format!(
                                    "px-3 py-1.5 rounded-full text-xs font-bold transition-all border {}",
                                    if active { "bg-green-600 border-green-500 text-white shadow-md shadow-green-600/20" } else { "bg-slate-900 border-slate-700 text-slate-400 hover:text-white" }
                                )
                            }
                        >
                            "✅ Tasks"
                        </button>
                        <button 
                            type="button"
                            on:click=move |_| {
                                if selected_topic.get() == "Ideas" {
                                    set_selected_topic.set(String::new());
                                } else {
                                    set_selected_topic.set("Ideas".to_string());
                                }
                            }
                            class=move || {
                                let active = selected_topic.get() == "Ideas";
                                format!(
                                    "px-3 py-1.5 rounded-full text-xs font-bold transition-all border {}",
                                    if active { "bg-yellow-600 border-yellow-500 text-white shadow-md shadow-yellow-600/20" } else { "bg-slate-900 border-slate-700 text-slate-400 hover:text-white" }
                                )
                            }
                        >
                            "💡 Ideas"
                        </button>
                        <button 
                            type="button"
                            on:click=move |_| {
                                if selected_topic.get() == "General" {
                                    set_selected_topic.set(String::new());
                                } else {
                                    set_selected_topic.set("General".to_string());
                                }
                            }
                            class=move || {
                                let active = selected_topic.get() == "General";
                                format!(
                                    "px-3 py-1.5 rounded-full text-xs font-bold transition-all border {}",
                                    if active { "bg-slate-700 border-slate-600 text-white shadow-md" } else { "bg-slate-900 border-slate-700 text-slate-400 hover:text-white" }
                                )
                            }
                        >
                            "📁 General"
                        </button>
                    </div>
                    <input 
                        type="text" 
                        placeholder="Enter custom topic or select one above..."
                        class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm focus:border-blue-500 outline-none transition-all mb-4"
                        prop:value=move || selected_topic.get()
                        on:input=move |ev| set_selected_topic.set(event_target_value(&ev))
                    />

                    <label class="block text-xs font-bold text-slate-400 mb-2 uppercase">"Note Content"</label>
                    <textarea 
                        placeholder="Enter your note, shared content, or reminder..."
                        class="w-full bg-slate-900 border border-slate-700 rounded-lg p-4 text-sm h-48 focus:border-blue-500 outline-none transition-all resize-none"
                        prop:value=move || note_content.get()
                        on:input=move |ev| set_note_content.set(event_target_value(&ev))
                    ></textarea>
                </div>

                <div class="flex justify-between items-center">
                    <div class="flex-1 mr-4">
                        <Show when=move || note_status.get().is_some()>
                            {move || {
                                let (msg, is_success) = note_status.get().unwrap_or_default();
                                let class = if is_success {
                                    "p-2 rounded-lg bg-green-900/30 border border-green-500/50 text-green-400 text-xs"
                                } else {
                                    "p-2 rounded-lg bg-red-900/30 border border-red-500/50 text-red-400 text-xs"
                                };
                                view! { <div class=class>{msg}</div> }
                            }}
                        </Show>
                    </div>
                    <div class="flex gap-4">
                        <button 
                            on:click=on_ask_agent
                            disabled=move || is_note_loading.get()
                            class="bg-purple-600 hover:bg-purple-500 text-white px-6 py-3 rounded-lg font-bold transition-all shadow-lg shadow-purple-600/20 disabled:opacity-50 min-w-[180px]">
                            {move || if is_note_loading.get() { "Sending..." } else { "Ask to personal agent" }}
                        </button>
                        <button 
                            on:click=on_save_note
                            disabled=move || is_note_loading.get()
                            class="bg-blue-600 hover:bg-blue-500 px-8 py-3 rounded-lg font-bold transition-all shadow-lg shadow-blue-600/20 disabled:opacity-50 min-w-[160px]">
                            {move || if is_note_loading.get() { "Saving..." } else { "Save to Vault" }}
                        </button>
                    </div>
                </div>
            </div>

            <div class="bg-slate-800/50 p-4 rounded-xl border border-slate-700/50">
                <div class="flex items-start gap-3">
                    <span class="text-xl">"💡"</span>
                    <div>
                        <p class="text-sm font-bold text-slate-300">"Pro Tip"</p>
                        <p class="text-xs text-slate-500">"You can share content to this page from other apps using your device's share menu. The shared content will appear here automatically."</p>
                    </div>
                </div>
            </div>


        </div>
    }
}

fn detect_topic(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.contains("http://") || trimmed.contains("https://") {
        "Links".to_string()
    } else {
        let verbs = ["do", "check", "get", "run", "find", "ask", "create", "list", "remind"];
        let lowercase_trimmed = trimmed.to_lowercase();
        let starts_with_verb = verbs.iter().any(|&verb| {
            if lowercase_trimmed.starts_with(verb) {
                let len = verb.len();
                if lowercase_trimmed.len() == len {
                    true
                } else {
                    let next_char = lowercase_trimmed.chars().nth(len);
                    matches!(next_char, Some(' ') | Some('\t') | Some('\r') | Some('\n') | Some(',') | Some('.') | Some('!') | Some('?'))
                }
            } else {
                false
            }
        });
        if starts_with_verb {
            "Tasks".to_string()
        } else {
            "General".to_string()
        }
    }
}

