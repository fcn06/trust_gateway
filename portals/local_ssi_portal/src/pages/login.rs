//! Login page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::RegistrationCookie;
use crate::auth::{perform_webauthn_register, perform_webauthn_login};

#[component]
pub fn Login(
    base_url: String,
    set_is_logged_in: WriteSignal<bool>,
    set_username: WriteSignal<String>,
    set_token: WriteSignal<String>,
    set_user_id: WriteSignal<String>,
    set_registration_cookie: WriteSignal<Option<RegistrationCookie>>,
) -> impl IntoView {
    let (user_input, set_user_input) = signal(String::new());
    let (invite_input, set_invite_input) = signal(String::new());
    let (show_invite, set_show_invite) = signal(false);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (is_loading, set_is_loading) = signal(false);
    let (is_register_mode, set_is_register_mode) = signal(false);

    let api_base = store_value(base_url);
    
    let on_register = move |_| {
        let username = user_input.get();
        if username.is_empty() { return; }
        set_is_loading.set(true);
        set_error_msg.set(None);
        
        let ab = api_base.get_value();
        let invite_code = {
            let code = invite_input.get().trim().to_uppercase();
            if code.is_empty() { None } else { Some(code) }
        };
        spawn_local(async move {
            match perform_webauthn_register(&ab, &username, invite_code).await {
                Ok(cookie_opt) => {
                    log::info!("Registration successful for {}", username);
                    if let Some(cookie) = cookie_opt {
                        set_registration_cookie.set(Some(cookie));
                    }
                    set_error_msg.set(Some("Registration successful! Now please sign in.".to_string()));
                    set_is_register_mode.set(false);
                },
                Err(e) => {
                    log::error!("Registration error: {:?}", e);
                    set_error_msg.set(Some(format!("Registration failed: {}", e)));
                }
            }
            set_is_loading.set(false);
        });
    };

    let on_continue = move |_| {
        let username = user_input.get();
        if username.is_empty() { return; }
        set_is_loading.set(true);
        set_error_msg.set(None);

        let ab = api_base.get_value();
        
        if is_register_mode.get() {
            on_register(());
            return;
        }

        spawn_local(async move {
            match perform_webauthn_login(&ab, &username).await {
                Ok((token_val, uid, cookie)) => {
                    if token_val.is_empty() {
                        set_error_msg.set(Some("Login failed: no token received".to_string()));
                    } else {
                        log::info!("Login successful for {}", username);
                        set_token.set(token_val);
                        set_user_id.set(uid);
                        set_username.set(username);
                        set_registration_cookie.set(Some(cookie));
                        
                        // Check for return_to parameter in the URL and redirect if present
                        if let Some(win) = web_sys::window() {
                            if let Ok(search) = win.location().search() {
                                if !search.is_empty() {
                                    if let Ok(params) = web_sys::UrlSearchParams::new_with_str(&search) {
                                        if let Some(return_to) = params.get("return_to") {
                                            log::info!("Redirecting to return_to: {}", return_to);
                                            let _ = win.location().set_href(&return_to);
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Default fallback: advance to the portal dashboard
                        set_is_logged_in.set(true);
                    }
                },
                Err(e) => {
                    log::info!("Login error (likely user not found): {:?}, switching to register mode", e);
                    set_is_register_mode.set(true);
                    set_error_msg.set(Some("User not found. Please provide an invite code if you have one, then click Continue to create an account.".to_string()));
                }
            }
            set_is_loading.set(false);
        });
    };

    view! {
        <div class="flex items-center justify-center min-h-screen bg-slate-950">
            <div class="bg-slate-900 p-8 rounded-2xl border border-slate-800 shadow-2xl w-full max-w-md">
                <div class="text-center mb-8">
                    <h2 class="text-3xl font-bold text-white mb-2">"Agent in a Box"</h2>
                    <p class="text-slate-400">"Your AI agent, under your control."</p>
                </div>
                <div class="space-y-5">
                    <div>
                        <label class="block text-sm font-medium text-slate-400 mb-2">"Username"</label>
                        <input
                            type="text"
                            on:input=move |ev| set_user_input.set(event_target_value(&ev))
                            class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-white placeholder-slate-600"
                            placeholder="Enter your username"
                        />
                    </div>

                    // Collapsible invite code section (only shown if in register mode or explicitly opened)
                    <Show when=move || is_register_mode.get() || show_invite.get()>
                        <div class="animate-in fade-in slide-in-from-top-2 duration-300">
                            <label class="block text-sm font-medium text-slate-400 mb-2">"Invite Code (Optional)"</label>
                            <input
                                type="text"
                                on:input=move |ev| set_invite_input.set(event_target_value(&ev))
                                class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-white font-mono tracking-widest text-center uppercase placeholder-slate-600"
                                placeholder="e.g. A3F29B"
                                maxlength="6"
                            />
                        </div>
                    </Show>

                    <Show when=move || !is_register_mode.get() && !show_invite.get()>
                        <button
                            on:click=move |_| set_show_invite.set(true)
                            class="text-xs text-blue-400 hover:text-blue-300 transition-colors w-full text-center"
                        >
                            "Have an invite code?"
                        </button>
                    </Show>
                    
                    <button
                        on:click=on_continue
                        disabled=move || is_loading.get()
                        class="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-3 rounded-lg transition-all shadow-lg shadow-blue-900/20 disabled:opacity-50 disabled:cursor-not-allowed mt-2"
                    >
                        {move || if is_loading.get() {
                            "Please wait..."
                        } else if is_register_mode.get() {
                            "Create Account"
                        } else {
                            "Continue"
                        }}
                    </button>

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
                            <span class="text-xs font-medium">"Your biometric data remains on this device."</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
