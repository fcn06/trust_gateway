//! Onboarding page component for new users.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::{RegistrationCookie, SendMessageRequest};
use crate::auth::{perform_webauthn_register, perform_webauthn_login};
use crate::api;

#[component]
pub fn Onboarding(
    base_url: String,
    username: ReadSignal<String>,
    set_is_logged_in: WriteSignal<bool>,
    set_username: WriteSignal<String>,
    set_token: WriteSignal<String>,
    set_user_id: WriteSignal<String>,
    set_registration_cookie: WriteSignal<Option<RegistrationCookie>>,
    set_current_path: WriteSignal<String>,
    set_active_section: WriteSignal<String>,
) -> impl IntoView {
    let (nickname, set_nickname) = signal(username.get());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (is_loading, set_is_loading) = signal(false);
    let (status_msg, set_status_msg) = signal(String::new());

    let api_base = store_value(base_url);

    let on_create_agent = move |_| {
        let name = nickname.get().trim().to_string();
        if name.is_empty() { return; }
        
        set_is_loading.set(true);
        set_error_msg.set(None);
        set_status_msg.set("Creating passkey...".to_string());
        
        let ab = api_base.get_value();
        spawn_local(async move {
            // Step 1: WebAuthn Passkey Registration
            match perform_webauthn_register(&ab, &name, None).await {
                Ok(cookie_opt) => {
                    log::info!("Biometric registration successful for {}", name);
                    
                    // Set username to pre-fill on login screen
                    set_username.set(name);
                    
                    if let Some(cookie) = cookie_opt {
                        set_registration_cookie.set(Some(cookie));
                    }
                    
                    // Redirect to login page with registered query parameter
                    if let Some(win) = web_sys::window() {
                        if let Ok(history) = win.history() {
                            let _ = history.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/login?registered=true"));
                            set_current_path.set("/login".to_string());
                        }
                    }
                }
                Err(e) => {
                    log::error!("Biometric registration failed: {}", e);
                    set_error_msg.set(Some(format!("Registration failed: {}", e)));
                }
            }
            set_is_loading.set(false);
        });
    };

    let on_go_to_login = move |_| {
        if let Some(win) = web_sys::window() {
            if let Ok(history) = win.history() {
                let _ = history.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/login"));
                set_current_path.set("/login".to_string());
            }
        }
    };

    view! {
        <div class="flex items-center justify-center min-h-screen bg-slate-950">
            <div class="bg-slate-900 p-8 rounded-2xl border border-slate-800 shadow-2xl w-full max-w-md">
                <div class="text-center mb-8">
                    <h2 class="text-3xl font-bold text-white mb-2 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">"Create My Agent"</h2>
                    <p class="text-slate-400 text-sm">"Get started with your biometric identity in seconds."</p>
                    <p class="text-slate-500 text-xs mt-2">"TouchID/FaceID passkey setup — secure and passwordless."</p>
                    <div class="border border-amber-500/20 bg-amber-500/5 p-3 rounded-lg text-xs text-amber-400 text-center mt-4">
                        "⚠️ Sandbox Preview — Ephemeral testing environment."
                    </div>
                </div>
                <div class="space-y-5">
                    <div>
                        <label class="block text-sm font-medium text-slate-400 mb-2">"Choose a Nickname"</label>
                        <input
                             type="text"
                             on:input=move |ev| set_nickname.set(event_target_value(&ev))
                             class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-white placeholder-slate-600 font-medium"
                             placeholder="e.g. Fred"
                             prop:value=move || nickname.get()
                             disabled=move || is_loading.get()
                        />
                    </div>

                    <button
                        on:click=on_create_agent
                        disabled=move || nickname.get().trim().is_empty() || is_loading.get()
                        class="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 rounded-lg transition-all shadow-lg shadow-blue-900/20 disabled:opacity-50 disabled:cursor-not-allowed mt-2 flex justify-center items-center gap-2"
                    >
                        <Show when=move || is_loading.get()>
                            <div class="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
                            {move || status_msg.get()}
                        </Show>
                        <Show when=move || !is_loading.get()>
                            "Create My Agent"
                        </Show>
                    </button>

                    <div class="text-center mt-4 pt-2">
                        <button
                            on:click=on_go_to_login
                            class="text-xs text-blue-400 hover:text-blue-300 transition-colors font-medium"
                        >
                            "Already have an account? Sign In"
                        </button>
                    </div>

                    <Show when=move || error_msg.get().is_some()>
                        <div class="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm text-center animate-in fade-in duration-300">
                            {move || error_msg.get()}
                        </div>
                    </Show>

                    <div class="mt-8 pt-6 border-t border-slate-800 text-center">
                        <div class="inline-flex items-center justify-center space-x-2 text-emerald-400/90 bg-emerald-400/10 px-4 py-2 rounded-full">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                            <span class="text-xs font-medium">"Your biometric credentials remain secure on this device."</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
