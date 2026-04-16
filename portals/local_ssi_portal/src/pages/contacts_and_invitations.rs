//! Contacts & Invitations — tabbed container component.
//!
//! Tab 1 (default): **Contacts** – send / accept / refuse contact requests.
//! Tab 2: **Invitations** – generate an OOB invitation or accept one.

use leptos::prelude::*;

use crate::types::EnrichedIdentity;
use crate::pages::{ContactRequestsSection, InvitationsSection};

#[component]
pub fn ContactsAndInvitations(
    base_url: String,
    token: String,
    identities: ReadSignal<Vec<EnrichedIdentity>>,
) -> impl IntoView {
    let (active_tab, set_active_tab) = signal("contacts".to_string());

    let base_url_a = base_url.clone();
    let base_url_b = base_url.clone();
    let token_a = token.clone();
    let token_b = token.clone();

    view! {
        <div class="max-w-4xl mx-auto w-full space-y-6">
            // ── Tab Bar ──────────────────────────────────────────────
            <div class="flex gap-1 bg-slate-800/60 p-1.5 rounded-xl border border-slate-700/60 backdrop-blur-sm">
                <button
                    on:click=move |_| set_active_tab.set("contacts".to_string())
                    class=move || {
                        let base = "flex-1 relative py-2.5 rounded-lg text-sm font-semibold transition-all duration-200 flex items-center justify-center gap-2";
                        if active_tab.get() == "contacts" {
                            format!("{} bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/25", base)
                        } else {
                            format!("{} text-slate-400 hover:text-white hover:bg-slate-700/50", base)
                        }
                    }
                >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    </svg>
                    "Contacts"
                </button>
                <button
                    on:click=move |_| set_active_tab.set("invitations".to_string())
                    class=move || {
                        let base = "flex-1 relative py-2.5 rounded-lg text-sm font-semibold transition-all duration-200 flex items-center justify-center gap-2";
                        if active_tab.get() == "invitations" {
                            format!("{} bg-gradient-to-r from-purple-600 to-purple-500 text-white shadow-lg shadow-purple-500/25", base)
                        } else {
                            format!("{} text-slate-400 hover:text-white hover:bg-slate-700/50", base)
                        }
                    }
                >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                    </svg>
                    "Invitations"
                </button>
            </div>

            // ── Tab Content ──────────────────────────────────────────
            <div>
                <Show when=move || active_tab.get() == "contacts">
                    <ContactRequestsSection base_url=base_url_a.clone() token=token_a.clone() identities=identities />
                </Show>
                <Show when=move || active_tab.get() == "invitations">
                    <InvitationsSection base_url=base_url_b.clone() token=token_b.clone() />
                </Show>
            </div>
        </div>
    }
}
