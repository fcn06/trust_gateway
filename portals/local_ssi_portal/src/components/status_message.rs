//! Status message component for feedback display.

use leptos::prelude::*;

#[component]
pub fn StatusMessage(
    message: ReadSignal<Option<(String, bool)>>
) -> impl IntoView {
    view! {
        <Show when=move || message.get().is_some()>
            {move || {
                let (msg, is_success) = message.get().unwrap_or_default();
                let class = if is_success {
                    "p-3 rounded-lg bg-green-900/30 border border-green-500/50 text-green-400 text-sm"
                } else {
                    "p-3 rounded-lg bg-red-900/30 border border-red-500/50 text-red-400 text-sm"
                };
                view! { <div class=class>{msg}</div> }
            }}
        </Show>
    }
}
