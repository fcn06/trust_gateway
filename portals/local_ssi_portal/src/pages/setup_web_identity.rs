use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use crate::api;

#[component]
pub fn SetupWebIdentity(
    base_url: String, 
    token: String, 
) -> impl IntoView {
    let (web_domain, set_web_domain) = signal(String::new());
    let (did_web_doc, set_did_web_doc) = signal(Option::<String>::None);
    let (is_generating_web, set_generating_web) = signal(false);

    let base_url_for_web = store_value(base_url);
    let token_for_web = store_value(token);

    let on_generate_web = move |_| {
        let domain = web_domain.get();
        if domain.is_empty() { return; }
        set_generating_web.set(true);
        let tt = token_for_web.get_value();
        let ab = base_url_for_web.get_value();
        spawn_local(async move {
            let req = crate::types::GenerateDidWebRequest { domain };
            match api::generate_did_web(&ab, req, tt).await {
                Ok(doc) => {
                    set_did_web_doc.set(Some(serde_json::to_string_pretty(&doc).unwrap_or_default()));
                },
                Err(e) => log::error!("Failed to generate did:web: {}", e),
            }
            set_generating_web.set(false);
        });
    };

    view! {
        <div class="space-y-6 text-white max-w-4xl mx-auto">
            <h2 class="text-2xl font-bold">"Setup Web Identity"</h2>
            <div class="p-6 bg-slate-800 rounded-2xl border border-slate-700 shadow-xl space-y-4">
                <h3 class="text-xl font-bold text-white">"Setup Web Identity (did:web)"</h3>
                <div class="flex gap-4 items-center">
                    <input 
                        type="text" 
                        placeholder="example.com"
                        prop:value=move || web_domain.get()
                        on:input=move |ev| set_web_domain.set(event_target_value(&ev))
                        class="bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm focus:ring-2 focus:ring-purple-500 outline-none w-full max-w-sm"
                    />
                    <button 
                        on:click=on_generate_web
                        disabled=move || is_generating_web.get() || web_domain.get().is_empty()
                        class="bg-purple-600 hover:bg-purple-500 px-6 py-3 rounded-lg font-bold transition-all shadow-lg shadow-purple-600/20 disabled:opacity-50">
                        {move || if is_generating_web.get() { "Generating..." } else { "Generate Document" }}
                    </button>
                </div>

                <Show when=move || did_web_doc.get().is_some()>
                    <div class="mt-4 p-4 bg-slate-900 rounded-lg border border-purple-500/30">
                        <p class="text-sm text-slate-300 font-bold mb-2">
                            "Host this file exactly at: "
                            <span class="text-purple-400 font-mono">
                                {move || format!("https://{}/.well-known/did.json", web_domain.get())}
                            </span>
                        </p>
                        <textarea 
                            readonly=true 
                            class="w-full bg-slate-950 text-emerald-400 font-mono text-xs p-4 rounded mt-2 border border-slate-800 h-48 focus:outline-none"
                            prop:value=move || did_web_doc.get().unwrap_or_default()
                        />
                        <button 
                            on:click=move |_| {
                                if let Some(doc) = did_web_doc.get() {
                                    use wasm_bindgen::JsCast;
                                    let href = format!("data:application/json;charset=utf-8,{}", web_sys::js_sys::encode_uri_component(&doc));
                                    let a = web_sys::window().unwrap().document().unwrap().create_element("a").unwrap();
                                    let _ = a.set_attribute("href", &href);
                                    let _ = a.set_attribute("download", "did.json");
                                    if let Ok(a_html) = a.dyn_into::<web_sys::HtmlElement>() {
                                        a_html.click();
                                    }
                                }
                            }
                            class="mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded text-sm font-bold shadow-lg shadow-emerald-600/20"
                        >
                            "Download did.json"
                        </button>
                    </div>
                </Show>
            </div>
        </div>
    }
}
