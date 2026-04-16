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
                },
                Err(e) => {
                    log::error!("Registration error: {:?}", e);
                    set_error_msg.set(Some(format!("Registration failed: {}", e)));
                }
            }
            set_is_loading.set(false);
        });
    };

    let on_login = move |_| {
        let username = user_input.get();
        if username.is_empty() { return; }
        set_is_loading.set(true);
        set_error_msg.set(None);

        let ab = api_base.get_value();
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
                        set_is_logged_in.set(true);
                    }
                },
                Err(e) => {
                    log::error!("Login error: {:?}", e);
                    set_error_msg.set(Some(format!("Login failed: {}", e)));
                }
            }
            set_is_loading.set(false);
        });
    };

    view! {
        <div class="flex items-center justify-center min-h-screen">
            <div class="bg-slate-800 p-8 rounded-2xl border border-slate-700 shadow-2xl w-full max-w-md">
                <h2 class="text-2xl font-bold mb-6 text-center">"Sovereign Access"</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-400 mb-1">"Username"</label>
                        <input
                            type="text"
                            on:input=move |ev| set_user_input.set(event_target_value(&ev))
                            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all text-white"
                            placeholder="e.g. alice"
                        />
                    </div>

                    // Collapsible invite code section
                    <div>
                        <button
                            on:click=move |_| set_show_invite.set(!show_invite.get())
                            class="text-xs text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1"
                        >
                            {move || if show_invite.get() { "▾ Hide invite code" } else { "▸ Have an invite code?" }}
                        </button>
                        <Show when=move || show_invite.get()>
                            <div class="mt-2">
                                <input
                                    type="text"
                                    on:input=move |ev| set_invite_input.set(event_target_value(&ev))
                                    class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 focus:ring-2 focus:ring-amber-500 focus:outline-none transition-all text-white font-mono tracking-widest text-center uppercase"
                                    placeholder="e.g. A3F29B"
                                    maxlength="6"
                                />
                                <p class="text-xs text-gray-500 mt-1">"Enter the 6-character code from your team owner."</p>
                            </div>
                        </Show>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <button
                            on:click=on_register
                            disabled=move || is_loading.get()
                            class="bg-slate-700 border border-slate-600 hover:bg-slate-600 text-white font-bold py-3 rounded-lg transition-all disabled:opacity-50"
                        >
                            "Sign Up"
                        </button>
                        <button
                            on:click=on_login
                            disabled=move || is_loading.get()
                            class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg transition-all shadow-lg shadow-blue-600/20 disabled:opacity-50"
                        >
                            "Sign In"
                        </button>
                    </div>

                    <Show when=move || error_msg.get().is_some()>
                        <div class="p-3 rounded bg-red-900/20 border border-red-500/50 text-red-400 text-xs text-center">
                            {move || error_msg.get()}
                        </div>
                    </Show>

                    <p class="text-xs text-center text-gray-400 mt-4">
                        "Your biometric data remains on this device."
                    </p>
                </div>
            </div>
        </div>
    }
}
