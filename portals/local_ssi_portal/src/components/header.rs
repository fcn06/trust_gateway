//! Header component with navigation.

use leptos::prelude::*;
use crate::types::{PortalConfig, RegistrationCookie};
use crate::utils::delete_cookie;

#[component]
pub fn Header(
    username: ReadSignal<String>,
    config: ReadSignal<PortalConfig>,
    active_section: ReadSignal<String>,
    set_active_section: WriteSignal<String>,
    show_mobile_menu: ReadSignal<bool>,
    set_show_mobile_menu: WriteSignal<bool>,
    registration_cookie: ReadSignal<Option<RegistrationCookie>>,
    set_is_logged_in: WriteSignal<bool>,
) -> impl IntoView {
    view! {
        <header class="bg-slate-800 border-b border-slate-700 p-4 flex justify-between items-center z-50">
            <div class="flex items-center gap-4">
                <button 
                    on:click=move |_| set_show_mobile_menu.update(|v| *v = !*v)
                    class="md:hidden text-gray-400 hover:text-white transition-colors"
                >
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7"></path>
                    </svg>
                </button>
                <button 
                    on:click=move |_| set_active_section.set("dashboard".to_string())
                    class="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent hover:opacity-80 transition-opacity"
                >
                    "Agent in a Box"
                </button>
                <nav class="hidden md:flex gap-4 ml-8">
                    <button on:click=move |_| set_active_section.set("dashboard".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Dashboard"</button>
                    <button on:click=move |_| set_active_section.set("identities".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Identities"</button>
                    <button on:click=move |_| set_active_section.set("messaging".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Messaging"</button>
                    <button on:click=move |_| set_active_section.set("acl".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Approved Contacts"</button>
                    <button on:click=move |_| set_active_section.set("invitations".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Invitations"</button>
                    <button on:click=move |_| set_active_section.set("contact_requests".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Requests"</button>
                    <button on:click=move |_| set_active_section.set("profile".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Profile"</button>
                    <button on:click=move |_| set_active_section.set("self_service".to_string()) class="text-sm hover:text-blue-400 transition-colors">"Self Service"</button>
                </nav>
            </div>
            <div class="flex items-center gap-4">
                <Show when=move || registration_cookie.get().is_some()>
                    <div 
                        class="hidden lg:flex items-center gap-2 bg-purple-900/30 px-3 py-1 rounded-full border border-purple-500/30 cursor-pointer hover:bg-purple-900/50 transition-colors"
                        title="Click to copy Global Login Cookie"
                        on:click=move |_| {
                            if let Some(cookie) = registration_cookie.get() {
                                if let Ok(json) = serde_json::to_string(&cookie) {
                                    if let Some(win) = web_sys::window() {
                                        let nav = win.navigator();
                                        let clip = nav.clipboard();
                                        let _ = clip.write_text(&json);
                                        let _ = win.alert_with_message("✅ Global Login Cookie copied to clipboard!");
                                    }
                                }
                            }
                        }
                    >
                        <span class="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
                        <span class="text-xs text-purple-300 font-mono">
                            "Sovereign: " {move || registration_cookie.get().map(|c| c.aid.clone()).unwrap_or_default()}
                        </span>
                    </div>
                </Show>
                <span class="hidden sm:inline text-sm text-gray-400">{move || format!("User: {}", username.get())}</span>
                <button on:click=move |_| {
                    set_is_logged_in.set(false);
                    delete_cookie("ssi_token");
                    delete_cookie("ssi_username");
                    delete_cookie("ssi_user_id");
                    delete_cookie("ssi_registration_cookie");
                } class="text-xs bg-red-600/20 text-red-400 px-3 py-1 rounded hover:bg-red-600/40 transition-colors">"Logout"</button>
            </div>
        </header>
    }
}
