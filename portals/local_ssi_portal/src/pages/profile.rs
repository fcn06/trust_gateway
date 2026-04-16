//! Profile page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;

#[component]
pub fn Profile(base_url: String, token: String, user_id: String, username: String) -> impl IntoView {
    let (country, set_country) = signal(String::new());
    let (status, set_status) = signal(Option::<(String, bool)>::None);
    let (is_loading, set_loading) = signal(false);

    let base_url = store_value(base_url);
    let token = store_value(token);

    // Fetch profile on mount
    let bu = base_url.get_value();
    let tt = token.get_value();
    Effect::new(move |_| {
        let bu = bu.clone();
        let tt = tt.clone();
        spawn_local(async move {
            if let Ok(profile) = api::get_profile(&bu, tt).await {
                if let Some(c) = profile.country {
                    set_country.set(c);
                }
            }
        });
    });

    let on_save_profile = move |_| {
        set_loading.set(true);
        set_status.set(None);
        
        let ab = base_url.get_value();
        let tt = token.get_value();
        let c = country.get();
        
        spawn_local(async move {
            let mut profile = api::get_profile(&ab, tt.clone()).await.unwrap_or_default();
            profile.country = Some(c);
            
            match api::update_profile(&ab, profile, tt).await {
                Ok(_) => set_status.set(Some(("✅ Profile updated successfully!".to_string(), true))),
                Err(e) => set_status.set(Some((format!("❌ Failed: {}", e), false))),
            }
            set_loading.set(false);
        });
    };

    view! {
        <div class="space-y-6 text-white max-w-2xl mx-auto">
            <h2 class="text-2xl font-bold">"Manage Profile"</h2>
            
            <div class="bg-slate-800 p-8 rounded-2xl border border-slate-700 shadow-xl space-y-6">
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-slate-400 mb-2">"Username"</label>
                        <div class="w-full bg-slate-900/50 border border-slate-700 rounded-lg p-3 text-sm text-slate-500 cursor-not-allowed">
                            {username}
                        </div>
                        <p class="text-[11px] text-slate-500 mt-1">"Usernames are permanent and cannot be changed."</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-slate-400 mb-2">"User ID (UUID)"</label>
                        <div class="w-full bg-slate-900/50 border border-slate-700 rounded-lg p-3 text-sm text-slate-500 font-mono cursor-not-allowed">
                            {user_id}
                        </div>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-slate-400 mb-2">"Country of Residence"</label>
                        <input 
                            type="text" 
                            placeholder="e.g. France"
                            class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm focus:border-blue-500 outline-none transition-all"
                            prop:value=move || country.get()
                            on:input=move |ev| set_country.set(event_target_value(&ev))
                        />
                    </div>

                    <div class="flex justify-end pt-4">
                        <button 
                            on:click=on_save_profile
                            disabled=move || is_loading.get()
                            class="bg-blue-600 hover:bg-blue-500 px-6 py-2.5 rounded-lg font-bold transition-all disabled:opacity-50">
                            {move || if is_loading.get() { "Saving..." } else { "Save Changes" }}
                        </button>
                    </div>

                    <Show when=move || status.get().is_some()>
                        {move || {
                            let (msg, is_success) = status.get().unwrap_or_default();
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
        </div>
    }
}

