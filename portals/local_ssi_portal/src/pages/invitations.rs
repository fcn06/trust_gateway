//! Invitations page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::OobInvitation;

#[component]
pub fn InvitationsSection(base_url: String, token: String) -> impl IntoView {
    let (invitation, set_invitation) = signal(Option::<OobInvitation>::None);
    let (error, set_error) = signal(Option::<String>::None);
    let (success, set_success) = signal(Option::<String>::None);
    let (paste_input, set_paste) = signal(String::new());
    let (is_loading, set_loading) = signal(false);
    
    let base_url_v = store_value(base_url);
    let token_v = store_value(token);

    let on_generate = move |_| {
        set_loading.set(true);
        set_error.set(None);
        let tt = token_v.get_value();
        let ab = base_url_v.get_value();
        spawn_local(async move {
            match api::generate_invitation(&ab, tt).await {
                Ok(inv) => {
                    set_invitation.set(Some(inv));
                    log::info!("Invitation generated successfully");
                },
                Err(e) => {
                    set_error.set(Some(format!("Failed to generate invitation: {}", e)));
                }
            }
            set_loading.set(false);
        });
    };

    let on_accept = move |_| {
        let data = paste_input.get();
        if data.is_empty() {
            set_error.set(Some("Please paste invitation JSON".to_string()));
            return;
        }
        
        let invitation: OobInvitation = match serde_json::from_str(&data) {
            Ok(inv) => inv,
            Err(_) => {
                set_error.set(Some("Invalid invitation JSON format".to_string()));
                return;
            }
        };
        
        set_loading.set(true);
        set_error.set(None);
        set_success.set(None);
        
        let tt = token_v.get_value();
        let ab = base_url_v.get_value();
        spawn_local(async move {
            match api::accept_invitation(&ab, invitation, tt).await {
                Ok(_) => {
                    set_success.set(Some("Connection established! The contact has been added to your Approved Contacts.".to_string()));
                    set_paste.set(String::new());
                    log::info!("Invitation accepted successfully");
                },
                Err(e) => {
                    set_error.set(Some(format!("Failed to accept invitation: {}", e)));
                }
            }
            set_loading.set(false);
        });
    };

    view! {
        <div class="space-y-6 text-white">
            <h2 class="text-2xl font-bold">"Connection Invitations"</h2>
            
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

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl space-y-4">
                    <h3 class="font-bold text-lg">"Generate Invitation"</h3>
                    <p class="text-sm text-slate-400">"Create an invitation to share with others to establish a connection."</p>
                    <button 
                        on:click=on_generate
                        disabled=move || is_loading.get()
                        class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-lg font-bold transition-all disabled:opacity-50">
                        {move || if is_loading.get() { "Generating..." } else { "Generate New Invitation" }}
                    </button>
                    
                    <Show when=move || invitation.get().is_some()>
                        <div class="bg-slate-900 p-4 rounded-xl border border-blue-500/30 space-y-3">
                            <div class="flex justify-between items-center">
                                <span class="text-xs text-blue-400 font-bold uppercase">"Your Invitation"</span>
                                <button
                                    on:click=move |_| {
                                        if let Some(inv) = invitation.get() {
                                            if let Ok(json) = serde_json::to_string_pretty(&inv) {
                                                if let Some(win) = web_sys::window() {
                                                    let nav = win.navigator();
                                                    let _ = nav.clipboard().write_text(&json);
                                                    let _ = win.alert_with_message("Copied to clipboard!");
                                                }
                                            }
                                        }
                                    }
                                    class="text-xs bg-blue-600/20 text-blue-400 px-2 py-1 rounded hover:bg-blue-600/40 transition-all">
                                    "Copy"
                                </button>
                            </div>
                            <pre class="text-[10px] text-slate-400 overflow-x-auto max-h-48 font-mono">
                                {move || invitation.get().map(|inv| serde_json::to_string_pretty(&inv).unwrap_or_default()).unwrap_or_default()}
                            </pre>
                        </div>
                    </Show>
                </div>

                <div class="bg-slate-800 p-6 rounded-2xl border border-slate-700 shadow-xl space-y-4">
                    <h3 class="font-bold text-lg">"Accept Invitation"</h3>
                    <p class="text-sm text-slate-400">"Paste an invitation JSON from someone else to connect with them."</p>
                    <textarea 
                        placeholder="Paste invitation JSON here..."
                        class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm h-32 font-mono"
                        prop:value=move || paste_input.get()
                        on:input=move |ev| set_paste.set(event_target_value(&ev))
                    ></textarea>
                    <button 
                        on:click=on_accept
                        disabled=move || is_loading.get()
                        class="w-full bg-green-600 hover:bg-green-500 py-3 rounded-lg font-bold transition-all disabled:opacity-50">
                        {move || if is_loading.get() { "Connecting..." } else { "Accept Invitation" }}
                    </button>
                </div>
            </div>
        </div>
    }
}
