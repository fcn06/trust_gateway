//! Local SSI Portal - A Self-Sovereign Identity management interface.
//!
//! This application provides a web interface for managing decentralized identities,
//! secure messaging, and peer-to-peer connections.

use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use reqwasm::http::Request;
use web_sys::window;

const EDITION: Option<&str> = option_env!("EDITION");

// === Module Declarations ===
pub mod types;
pub mod api;
pub mod auth;
pub mod utils;
pub mod pages;
pub mod components;

// === Re-exports ===
use types::{PortalConfig, RegistrationCookie, ConnectionPolicy, EnrichedIdentity};
use utils::{get_cookie, delete_cookie};

#[component]
fn App() -> impl IntoView {
    let (is_logged_in, set_is_logged_in) = signal(false);
    let (username, set_username) = signal(String::new());
    let (token, set_token) = signal(String::new());
    let (user_id, set_user_id) = signal(String::new());
    let (active_section, set_active_section) = signal(
        if EDITION.unwrap_or("professional") != "community" { "inbox".to_string() } else { "validation".to_string() }
    );
    let (policies, set_policies) = signal(Vec::<ConnectionPolicy>::new());
    let (identities, set_identities) = signal(Vec::<EnrichedIdentity>::new());
    let (active_did, set_active_did) = signal(String::new());
    let (refresh_trigger, set_refresh_trigger) = signal(0);
    let (show_mobile_menu, set_show_mobile_menu) = signal(false);
    let (show_audit_menu, set_show_audit_menu) = signal(false);
    let (config, set_config) = signal(PortalConfig::default());
    let (shared_msg, set_shared_msg) = signal(String::new());
    let (registration_cookie, set_registration_cookie) = signal(Option::<RegistrationCookie>::None);
    let (sidebar_collapsed, set_sidebar_collapsed) = signal(false);

    let messaging_enabled = EDITION.unwrap_or("professional") != "community";

    // Share Target handling
    Effect::new(move |_| {
        if let Some(win) = window() {
            if let Ok(search) = win.location().search() {
                if !search.is_empty() {
                    let params = web_sys::UrlSearchParams::new_with_str(&search).unwrap();
                    let title = params.get("share_title").unwrap_or_default();
                    let text = params.get("share_text").unwrap_or_default();
                    let url = params.get("share_url").unwrap_or_default();

                    let mut msg = String::new();
                    if !title.is_empty() { msg.push_str(&format!("{}\n", title)); }
                    if !text.is_empty() { msg.push_str(&text); }
                    if !url.is_empty() { 
                        if !msg.is_empty() { msg.push_str("\n"); }
                        msg.push_str(&url); 
                    }

                    if !msg.is_empty() {
                        set_shared_msg.set(msg);
                        set_active_section.set("self_service".to_string());
                        
                        if let Ok(history) = win.history() {
                            let _ = history.replace_state_with_url(&JsValue::NULL, "", Some("/"));
                        }
                    }
                }
            }
        }
    });

    // Load config on startup
    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(resp) = Request::get("/config.json").send().await {
                if let Ok(c) = resp.json::<PortalConfig>().await {
                    set_config.set(c);
                }
            }
        });
    });

    // Load session from cookies on startup
    Effect::new(move |_| {
        let tok = get_cookie("ssi_token").unwrap_or_default();
        let user = get_cookie("ssi_username").unwrap_or_default();
        let uid = get_cookie("ssi_user_id").unwrap_or_default();
        
        if !user.is_empty() {
            set_token.set(tok);
            set_username.set(user);
            set_user_id.set(uid);
            set_is_logged_in.set(true);
        }

        // Load Registration Cookie
        if let Some(cookie_encoded) = get_cookie("ssi_registration_cookie") {
            if let Ok(cookie_str) = js_sys::decode_uri_component(&cookie_encoded) {
                 let cookie_str = String::from(cookie_str);
                 if let Ok(cookie) = serde_json::from_str::<RegistrationCookie>(&cookie_str) {
                      set_registration_cookie.set(Some(cookie));
                 }
            }
        }
    });

    // Fetch active DID when logged in
    Effect::new(move |_| {
        let logged_in = is_logged_in.get();
        let tok = token.get();
        let api_base = config.get().api_base_url;
        let _ = refresh_trigger.get();
        if logged_in && !api_base.is_empty() {
            spawn_local(async move {
                if let Ok(did) = api::get_active_did(&api_base, tok).await {
                    set_active_did.set(did);
                }
            });
        }
    });

    // Load policies and identities when logged in OR active_did changes OR refresh_trigger fires
    Effect::new(move |_| {
        let logged_in = is_logged_in.get();
        let tok = token.get();
        let api_base = config.get().api_base_url;
        let _active = active_did.get();
        let _refresh = refresh_trigger.get();

        if logged_in && !api_base.is_empty() {
            spawn_local(async move {
                if let Ok(list) = api::get_policies(&api_base, tok.clone()).await {
                    set_policies.set(list);
                }
                if let Ok(list) = api::list_identities(&api_base, tok.clone()).await {
                    set_identities.set(list);
                }
            });
        }
    });

    view! {
        <div class="min-h-screen bg-slate-900 font-sans text-white">
            <Show
                when=move || is_logged_in.get()
                fallback=move || {
                    let api_base = config.get().api_base_url;
                    view! { <pages::Login base_url=api_base set_is_logged_in set_username set_token set_user_id set_registration_cookie /> }
                }
            >
                <div class="flex h-screen overflow-hidden bg-slate-900">
                    // Sidebar (Desktop)
                    <aside class=move || format!("{} bg-slate-800 border-r border-slate-700 md:flex flex-col hidden z-40 transition-all duration-300 relative", if sidebar_collapsed.get() { "w-20" } else { "w-64" })>
                        <div class=move || format!("bg-slate-800 border-b border-slate-700 h-16 flex items-center transition-all duration-300 px-4 whitespace-nowrap overflow-hidden {}", if sidebar_collapsed.get() { "justify-center" } else { "justify-between" })>
                            <button 
                                on:click=move |_| set_active_section.set("unified_inbox".to_string()) 
                                class=move || format!("text-left transition-all duration-300 {}", if sidebar_collapsed.get() { "w-0 opacity-0 invisible" } else { "w-auto opacity-100" })
                            >
                                <span class="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent whitespace-nowrap cursor-pointer hover:opacity-80">"Agent in a Box"</span>
                            </button>
                            <button 
                                on:click=move |_| set_sidebar_collapsed.update(|v| *v = !*v) 
                                class="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-700 transition-all flex-shrink-0"
                            >
                                <svg class=move || format!("w-6 h-6 transform transition-transform {}", if sidebar_collapsed.get() { "rotate-180" } else { "" }) fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7"></path>
                                </svg>
                            </button>
                        </div>
                        <nav class="flex-1 overflow-y-auto p-4 space-y-6">
                            // Hub
                            <div>
                                <h3 class=move || format!("text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 transition-opacity {}", if sidebar_collapsed.get() { "opacity-0 invisible h-0" } else { "opacity-100 visible" })>"Hub"</h3>
                                <div class="space-y-1">
                                    <Show when=move || messaging_enabled>
                                        <button title="Unified Inbox" on:click=move |_| set_active_section.set("unified_inbox".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "unified_inbox" { "bg-blue-600/20 text-blue-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                                            <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Unified Inbox"</span>
                                        </button>
                                    </Show>
                                    <button title="Validation" on:click=move |_| set_active_section.set("validation".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "validation" { "bg-blue-600/20 text-blue-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Validation"</span>
                                    </button>
                                </div>
                            </div>
                            // My Network
                            <Show when=move || messaging_enabled>
                                <div>
                                    <h3 class=move || format!("text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 transition-opacity {}", if sidebar_collapsed.get() { "opacity-0 invisible h-0" } else { "opacity-100 visible" })>"My Network"</h3>
                                    <div class="space-y-1">
                                        <button title="Manage Identities" on:click=move |_| set_active_section.set("manage_identities".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "manage_identities" { "bg-purple-600/20 text-purple-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2"></path></svg>
                                            <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Manage Identities"</span>
                                        </button>
                                        <button title="Contact Requests" on:click=move |_| set_active_section.set("contact_requests".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "contact_requests" { "bg-purple-600/20 text-purple-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                                            <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Contacts & Invites"</span>
                                        </button>
                                        <button title="Setup Web Identity" on:click=move |_| set_active_section.set("setup_web_identity".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "setup_web_identity" { "bg-purple-600/20 text-purple-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
                                            <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Setup web Identity"</span>
                                        </button>
                                    </div>
                                </div>
                            </Show>
                            // Trust Center
                            <div>
                                <h3 class=move || format!("text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 transition-opacity {}", if sidebar_collapsed.get() { "opacity-0 invisible h-0" } else { "opacity-100 visible" })>"Trust Center"</h3>
                                <div class="space-y-1">
                                    <button title="Activity" on:click=move |_| set_active_section.set("activity".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "activity" { "bg-emerald-600/20 text-emerald-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Activity"</span>
                                    </button>
                                    <button title="Replay" on:click=move |_| set_active_section.set("replay".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "replay" { "bg-emerald-600/20 text-emerald-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Replay"</span>
                                    </button>
                                    <button title="Policy Builder" on:click=move |_| set_active_section.set("policy_builder".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "policy_builder" { "bg-emerald-600/20 text-emerald-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Policy Builder"</span>
                                    </button>
                                    <button title="Agent Registry" on:click=move |_| set_active_section.set("agent_registry".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "agent_registry" { "bg-emerald-600/20 text-emerald-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Agent Registry"</span>
                                    </button>
                                </div>
                            </div>
                            // Settings
                            <div>
                                <h3 class=move || format!("text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 transition-opacity {}", if sidebar_collapsed.get() { "opacity-0 invisible h-0" } else { "opacity-100 visible" })>"Settings"</h3>
                                <div class="space-y-1">
                                    <button title="Core" on:click=move |_| set_active_section.set("key".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "key" { "bg-slate-600/50 text-slate-200" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Core"</span>
                                    </button>
                                    <button title="Integrations" on:click=move |_| set_active_section.set("integrations".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "integrations" { "bg-slate-600/50 text-slate-200" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                        <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 011-1h1a2 2 0 100-4H7a1 1 0 01-1-1V7a1 1 0 011-1h3a1 1 0 001-1V4z"></path></svg>
                                        <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Integrations"</span>
                                    </button>
                                </div>
                            </div>
                            <Show when=move || config.get().kitchen_menu_visible>
                                <div>
                                    <h3 class=move || format!("text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 transition-opacity {}", if sidebar_collapsed.get() { "opacity-0 invisible h-0" } else { "opacity-100 visible" })>"Restaurant"</h3>
                                    <div class="space-y-1">
                                        <button title="Kitchen Orders" on:click=move |_| set_active_section.set("kitchen_orders".to_string()) class=move || format!("w-full text-left px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-3 {}", if active_section.get() == "kitchen_orders" { "bg-orange-600/20 text-orange-400" } else { "text-slate-400 hover:bg-slate-700 hover:text-white" })>
                                            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path></svg>
                                            <span class=move || if sidebar_collapsed.get() { "hidden" } else { "block" }>"Kitchen Orders"</span>
                                        </button>
                                    </div>
                                </div>
                            </Show>
                        </nav>
                        <div class="p-4 border-t border-slate-700 flex flex-col gap-2 relative overflow-hidden">
                            <div class=move || format!("text-xs text-slate-400 truncate transition-opacity {}", if sidebar_collapsed.get() { "opacity-0 invisible" } else { "opacity-100 visible" })>
                                {move || format!("User: {}", username.get())}
                            </div>
                            <button on:click=move |_| {
                                set_is_logged_in.set(false);
                                delete_cookie("ssi_token");
                                delete_cookie("ssi_username");
                                delete_cookie("ssi_user_id");
                                delete_cookie("ssi_registration_cookie");
                            } class=move || format!("w-full text-xs bg-red-600/20 text-red-400 py-1.5 rounded hover:bg-red-600/40 transition-all flex items-center justify-center {}", if sidebar_collapsed.get() { "px-0" } else { "px-3" })>
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                                <span class=move || if sidebar_collapsed.get() { "hidden" } else { "ml-2 block" }>"Logout"</span>
                            </button>
                        </div>
                    </aside>

                    // Mobile Sidebar Overlay
                    <Show when=move || show_mobile_menu.get()>
                        <div class="md:hidden fixed inset-0 z-50 bg-slate-900/95 backdrop-blur-sm flex flex-col p-4 space-y-4 touch-none overflow-y-auto">
                            <div class="flex justify-between items-center mb-4">
                                <button on:click=move |_| { set_active_section.set("unified_inbox".to_string()); set_show_mobile_menu.set(false); }>
                                    <span class="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent cursor-pointer">"Agent in a Box"</span>
                                </button>
                                <button on:click=move |_| set_show_mobile_menu.set(false) class="text-gray-400 hover:text-white">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                </button>
                            </div>
                            <div>
                                <h3 class="text-xs font-bold text-slate-500 uppercase">Hub</h3>
                                <div class="ml-2 mt-2 space-y-2">
                                    <Show when=move || messaging_enabled>
                                        <button on:click=move |_| { set_active_section.set("unified_inbox".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-blue-400">"Unified Inbox"</button>
                                    </Show>
                                    <button on:click=move |_| { set_active_section.set("validation".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-blue-400">"Validation"</button>
                                </div>
                            </div>
                            <Show when=move || messaging_enabled>
                                <div class="mt-4">
                                    <h3 class="text-xs font-bold text-slate-500 uppercase">My Network</h3>
                                    <div class="ml-2 mt-2 space-y-2">
                                        <button on:click=move |_| { set_active_section.set("manage_identities".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-purple-400">"Manage Identities"</button>
                                        <button on:click=move |_| { set_active_section.set("contact_requests".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-purple-400">"Contact Requests & Invitations"</button>
                                        <button on:click=move |_| { set_active_section.set("setup_web_identity".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-purple-400">"Setup web Identity"</button>
                                    </div>
                                </div>
                            </Show>
                            <div class="mt-4">
                                <h3 class="text-xs font-bold text-slate-500 uppercase">Trust Center</h3>
                                <div class="ml-2 mt-2 space-y-2">
                                    <button on:click=move |_| { set_active_section.set("activity".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-emerald-400">"Activity"</button>
                                    <button on:click=move |_| { set_active_section.set("replay".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-emerald-400">"Replay"</button>
                                    <button on:click=move |_| { set_active_section.set("policy_builder".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-emerald-400">"Policy Builder"</button>
                                    <button on:click=move |_| { set_active_section.set("agent_registry".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-emerald-400">"Agent Registry"</button>
                                </div>
                            </div>
                            <div class="mt-4">
                                <h3 class="text-xs font-bold text-slate-500 uppercase">Settings</h3>
                                <div class="ml-2 mt-2 space-y-2">
                                    <button on:click=move |_| { set_active_section.set("key".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-slate-300">"Core"</button>
                                    <button on:click=move |_| { set_active_section.set("integrations".to_string()); set_show_mobile_menu.set(false); } class="block w-full text-left text-slate-300">"Integrations"</button>
                                </div>
                            </div>
                        </div>
                    </Show>

                    <div class="flex-1 flex flex-col h-screen overflow-hidden relative">
                        <header class="md:hidden bg-slate-800 border-b border-slate-700 p-4 flex justify-between items-center z-40">
                            <div class="flex items-center gap-4">
                                <button on:click=move |_| set_show_mobile_menu.update(|v| *v = !*v) class="text-gray-400 hover:text-white transition-colors">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7"></path></svg>
                                </button>
                                <button on:click=move |_| set_active_section.set("unified_inbox".to_string())>
                                    <span class="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent cursor-pointer">"Agent in a Box"</span>
                                </button>
                            </div>
                        </header>
                        
                        <main class="flex-1 overflow-auto p-4 md:p-6 bg-slate-900">
                        {move || {
                            let api_base = config.get().api_base_url;
                            match active_section.get().as_str() {
                                "dashboard" => view! { <pages::Dashboard username=username.get() token=token.get() base_url=api_base.clone() /> }.into_any(),
                                "unified_inbox" | "inbox" | "hub" => view! { <pages::Inbox base_url=api_base.clone() token=token.get() policies=policies identities=identities refresh_trigger=refresh_trigger set_refresh_trigger=set_refresh_trigger /> }.into_any(),
                                "validation" => view! { <pages::EscalationRequestsSection base_url=api_base.clone() token=token.get() identities=identities /> }.into_any(),
                                "manage_identities" => view! { <pages::Identities base_url=api_base.clone() username=username.get() token=token.get() user_id=user_id.get() identities=identities set_identities=set_identities active_did=active_did set_active_did=set_active_did refresh_trigger=refresh_trigger set_refresh_trigger=set_refresh_trigger policies=policies /> }.into_any(),
                                "contact_requests" => view! { <pages::ContactsAndInvitations base_url=api_base.clone() token=token.get() identities=identities refresh_trigger=refresh_trigger set_refresh_trigger=set_refresh_trigger /> }.into_any(),
                                "setup_web_identity" => view! { <pages::SetupWebIdentity base_url=api_base.clone() token=token.get() /> }.into_any(),
                                "activity" | "trust_center" => view! { <pages::Activity base_url=api_base.clone() token=token.get() /> }.into_any(),
                                "replay" | "trust_replay" => view! { <pages::TrustReplay base_url=api_base.clone() token=token.get() /> }.into_any(),
                                "policy_builder" => view! { <pages::PolicyBuilder base_url=api_base.clone() token=token.get() /> }.into_any(),
                                "agent_registry" => view! { <pages::AgentRegistry base_url=api_base.clone() token=token.get() /> }.into_any(),
                                "key" | "settings" => view! { <pages::Settings base_url=api_base.clone() token=token.get() registration_cookie=registration_cookie /> }.into_any(),
                                "integrations" => view! { <pages::Integrations base_url=api_base.clone() connector_url=config.get().connector_url token=token.get() registration_cookie=registration_cookie /> }.into_any(),
                                "kitchen_orders" => {
                                    if config.get().kitchen_menu_visible {
                                        view! { <pages::KitchenOrders config=config.get() identities=identities registration_cookie=registration_cookie /> }.into_any()
                                    } else {
                                        view! { <pages::Inbox base_url=api_base.clone() token=token.get() policies=policies identities=identities refresh_trigger=refresh_trigger set_refresh_trigger=set_refresh_trigger /> }.into_any()
                                    }
                                },
                                "messaging" => view! { <pages::Messaging base_url=api_base.clone() username=username.get() token=token.get() policies=policies identities=identities initial_msg=shared_msg.get() /> }.into_any(),
                                "profile" => view! { <pages::Profile base_url=api_base.clone() token=token.get() user_id=user_id.get() username=username.get() /> }.into_any(),
                                "self_service" => view! { <pages::SelfService base_url=api_base.clone() token=token.get() initial_msg=shared_msg.get() /> }.into_any(),
                                _ => view! { <pages::Inbox base_url=api_base.clone() token=token.get() policies=policies identities=identities refresh_trigger=refresh_trigger set_refresh_trigger=set_refresh_trigger /> }.into_any(),
                            }
                        }}
                    </main>

                    // Universal Floating Action Button (FAB)
                    <div class="fixed bottom-6 right-6 z-50 group">
                        <button class="bg-blue-600 hover:bg-blue-500 text-white rounded-full p-4 shadow-xl z-50 flex items-center justify-center transition-all transform hover:scale-105 peer">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                        </button>
                        <div class="absolute right-0 bottom-full mb-4 opacity-0 group-hover:opacity-100 peer-hover:opacity-100 transition-all invisible group-hover:visible peer-hover:visible flex flex-col gap-2 items-end">
                            <Show when=move || messaging_enabled>
                                <button on:click=move |_| set_active_section.set("contact_requests".to_string()) class="bg-slate-800 border border-slate-700 hover:bg-slate-700 text-white px-4 py-2 rounded-lg shadow-lg whitespace-nowrap text-sm font-medium">
                                    "Add a contact"
                                </button>
                            </Show>
                            <button on:click=move |_| set_active_section.set("validation".to_string()) class="bg-slate-800 border border-slate-700 hover:bg-slate-700 text-white px-4 py-2 rounded-lg shadow-lg whitespace-nowrap text-sm font-medium">
                                "Review pending approvals"
                            </button>
                            <button on:click=move |_| set_active_section.set("policy_builder".to_string()) class="bg-slate-800 border border-slate-700 hover:bg-slate-700 text-white px-4 py-2 rounded-lg shadow-lg whitespace-nowrap text-sm font-medium">
                                "Adjust security rules"
                            </button>
                        </div>
                    </div>
                </div>
                </div>
            </Show>
        </div>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    _ = console_log::init_with_level(log::Level::Debug);
    leptos::mount::mount_to_body(App);
}
