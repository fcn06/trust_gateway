//! Self Service page component for personal notes and sharing.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::SendMessageRequest;

#[component]
pub fn SelfService(base_url: String, token: String, initial_msg: String) -> impl IntoView {
    let (note_content, set_note_content) = signal(initial_msg);
    let (note_status, set_note_status) = signal(Option::<(String, bool)>::None);
    let (is_note_loading, set_note_loading) = signal(false);

    // Recovery Phrase signals
    let (nickname, set_nickname) = signal(String::new());
    let (secret, set_secret) = signal(String::new());
    let (recovery_status, set_recovery_status) = signal(Option::<(String, bool)>::None);
    let (is_recovery_loading, set_is_recovery_loading) = signal(false);

    let base_url = store_value(base_url);
    let token = store_value(token);

    let on_save_note = move |_| {
        let content = note_content.get();
        if content.is_empty() {
            set_note_status.set(Some(("Please enter a note".to_string(), false)));
            return;
        }
        
        set_note_loading.set(true);
        set_note_status.set(None);
        
        let ab = base_url.get_value();
        let tt = token.get_value();
        
        spawn_local(async move {
            match api::get_active_did(&ab, tt.clone()).await {
                Ok(my_did) => {
                    let req = SendMessageRequest {
                        to: my_did,
                        body: content,
                        r#type: "https://didcomm.org/self-note/1.0/note".to_string(),
                        thid: None,
                    };
                    
                    match api::send_message(&ab, req, tt).await {
                        Ok(_) => {
                            set_note_status.set(Some(("✅ Note saved to your personal vault!".to_string(), true)));
                            set_note_content.set(String::new());
                        },
                        Err(e) => set_note_status.set(Some((format!("❌ Failed: {}", e), false))),
                    }
                },
                Err(e) => set_note_status.set(Some((format!("❌ No active identity: {}", e), false))),
            }
            set_note_loading.set(false);
        });
    };

    let on_save_recovery = move |_| {
        let nick = nickname.get();
        let sec = secret.get();
        if nick.is_empty() || sec.is_empty() {
            set_recovery_status.set(Some(("Please fill in both fields".to_string(), false)));
            return;
        }
        
        set_is_recovery_loading.set(true);
        set_recovery_status.set(None);
        
        let ab = base_url.get_value();
        let tt = token.get_value();
        spawn_local(async move {
            match api::set_recovery(&ab, nick, sec, tt).await {
                Ok(_) => {
                    set_recovery_status.set(Some(("✅ Recovery phrase saved successfully!".to_string(), true)));
                    set_nickname.set(String::new());
                    set_secret.set(String::new());
                },
                Err(e) => set_recovery_status.set(Some((format!("❌ Failed: {}", e), false))),
            }
            set_is_recovery_loading.set(false);
        });
    };

    view! {
        <div class="space-y-6 text-white max-w-2xl mx-auto">
            <h2 class="text-2xl font-bold">"Self Service"</h2>
            <p class="text-slate-400">"Send notes and content to yourself. Perfect for capturing shared content or personal reminders."</p>
            
            <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl space-y-4">
                <div>
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
                    <button 
                        on:click=on_save_note
                        disabled=move || is_note_loading.get()
                        class="bg-blue-600 hover:bg-blue-500 px-8 py-3 rounded-lg font-bold transition-all shadow-lg shadow-blue-600/20 disabled:opacity-50 min-w-[160px]">
                        {move || if is_note_loading.get() { "Saving..." } else { "Save to Vault" }}
                    </button>
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

            // Recovery Phrase Section
            <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl space-y-6">
                <div>
                    <h3 class="text-lg font-bold mb-2">"Recovery Phrase"</h3>
                    <p class="text-sm text-slate-400 mb-4">
                        "Set a recovery phrase to restore your identity if you lose access to this device. Keep this information safe!"
                    </p>
                </div>

                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Nickname"</label>
                        <input 
                            type="text" 
                            placeholder="e.g. my-backup-phrase"
                            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm focus:border-blue-500 outline-none transition-all"
                            prop:value=move || nickname.get()
                            on:input=move |ev| set_nickname.set(event_target_value(&ev))
                        />
                    </div>
                    
                    <div>
                        <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Recovery Phrase"</label>
                        <input 
                            type="password" 
                            placeholder="Enter a memorable phrase..."
                            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm focus:border-blue-500 outline-none transition-all"
                            prop:value=move || secret.get()
                            on:input=move |ev| set_secret.set(event_target_value(&ev))
                        />
                        <p class="text-[10px] text-slate-500 mt-1">"This phrase will be used to derive your recovery key. Make it memorable but unique."</p>
                    </div>

                    <button 
                        on:click=on_save_recovery
                        disabled=move || is_recovery_loading.get()
                        class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 py-3 rounded-lg font-bold transition-all shadow-lg shadow-blue-600/20 disabled:opacity-50">
                        {move || if is_recovery_loading.get() { "Saving..." } else { "Save Recovery Phrase" }}
                    </button>

                    <Show when=move || recovery_status.get().is_some()>
                        {move || {
                            let (msg, is_success) = recovery_status.get().unwrap_or_default();
                            let class = if is_success {
                                "p-3 rounded-lg bg-green-900/30 border border-green-500/50 text-green-400 text-sm"
                            } else {
                                "p-3 rounded-lg bg-red-900/30 border border-red-500/50 text-red-400 text-sm"
                            };
                            view! { <div class=class>{msg}</div> }
                        }}
                    </Show>
                </div>
            </div>

            // Security Info Section
            <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl">
                <h3 class="text-lg font-bold mb-4">"Security Info"</h3>
                <div class="space-y-3">
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-700">
                        <span class="text-sm text-slate-400">"Passkey Authentication"</span>
                        <span class="text-green-400 text-xs font-bold">"ENABLED"</span>
                    </div>
                    <div class="flex items-center justify-between p-3 bg-slate-900 rounded-lg border border-slate-700">
                        <span class="text-sm text-slate-400">"Device Binding"</span>
                        <span class="text-green-400 text-xs font-bold">"ACTIVE"</span>
                    </div>
                </div>
            </div>
        </div>
    }
}

