//! B2B DLP Policies Management page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::{B2bPolicy, UpdateB2bPolicyRequest};

#[component]
pub fn B2bPoliciesManager(
    base_url: String, 
    token: String, 
) -> impl IntoView {
    let (policies, set_policies) = signal(Vec::<B2bPolicy>::new());
    let (trigger, set_trigger) = signal(0);
    
    let token_store = store_value(token.clone());
    let base_url_store = store_value(base_url.clone());
    
    Effect::new(move |_| {
        let _ = trigger.get();
        let tt = token_store.get_value();
        let ab = base_url_store.get_value();
        spawn_local(async move {
            if let Ok(list) = api::get_b2b_policies(&ab, tt).await {
                set_policies.set(list);
            }
        });
    });
    
    let (did_input, set_did) = signal(String::new());
    let (prompt_input, set_prompt) = signal(String::new());

    let on_add = move |_| {
         let d = did_input.get();
         let p = prompt_input.get();
         if d.is_empty() || p.is_empty() { return; }
         
         let req = UpdateB2bPolicyRequest {
             partner_did: d,
             prompt: p,
         };
         
         let tt = token_store.get_value();
         let ab = base_url_store.get_value();
         spawn_local(async move {
             match api::update_b2b_policy(&ab, req, tt).await {
                 Ok(_) => {
                     set_trigger.update(|n| *n += 1);
                     set_did.set(String::new());
                     set_prompt.set(String::new());
                 },
                 Err(e) => log::error!("B2B policy update failed: {}", e),
             }
         });
    };

    view! {
        <div class="space-y-6 text-white bg-slate-800 p-6 rounded-2xl border border-slate-700">
            <div class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">"B2B Semantic Policies"</h2>
                    <p class="text-sm text-slate-400 mt-1">"Manage dynamic DLP prompts for your B2B partners."</p>
                </div>
                <button
                    on:click=move |_| set_trigger.update(|n| *n += 1)
                    class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-sm border border-slate-600">
                    "Refresh"
                </button>
            </div>
            
            <div class="bg-slate-900/50 p-4 rounded-xl border border-slate-700/50 mb-8 space-y-4">
                <h3 class="text-lg font-bold text-slate-300">"Create or Edit Policy"</h3>
                <div>
                    <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Partner DID"</label>
                    <input type="text" placeholder="did:web:companyB.com" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white"
                        prop:value=move || did_input.get()
                        on:input=move |ev| set_did.set(event_target_value(&ev)) />
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Semantic DLP Prompt"</label>
                    <textarea placeholder="You are an isolated semantic filter. Do NOT return raw JSON. Extract ONLY authorized fields..." 
                        class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white min-h-[100px] font-mono"
                        prop:value=move || prompt_input.get()
                        on:input=move |ev| set_prompt.set(event_target_value(&ev))></textarea>
                </div>
                <button on:click=on_add class="w-full bg-blue-600 hover:bg-blue-500 rounded font-bold py-2 shadow-lg shadow-blue-500/20 transition-all">"Deploy B2B Policy"</button>
            </div>
            
             <div class="space-y-4">
                 <h3 class="text-lg font-bold text-slate-300">"Active Policies"</h3>
                 <ul class="space-y-4">
                     <For each=move || policies.get() key=|p| format!("{}-{}", p.partner_did, p.prompt.len()) children=move |p| {
                         let did = p.partner_did.clone();
                         let prompt = p.prompt.clone();
                         view! {
                             <li class="bg-slate-900 p-4 rounded-xl border border-slate-700 flex flex-col gap-2 relative group overflow-hidden">
                                 <div class="flex justify-between items-center border-b border-slate-800 pb-2">
                                     <span class="font-bold font-mono text-sm text-emerald-400">{did.clone()}</span>
                                     <button 
                                         on:click=move |_| {
                                             set_did.set(did.clone());
                                             set_prompt.set(prompt.clone());
                                             // Scroll to top or just let them edit
                                         }
                                         class="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded transition-all text-xs font-bold border border-slate-600"
                                     >
                                         "Edit"
                                     </button>
                                 </div>
                                 <div class="text-xs font-mono text-slate-400 bg-slate-950 p-3 rounded overflow-x-auto whitespace-pre-wrap mt-2">
                                     {p.prompt.clone()}
                                 </div>
                             </li>
                         }
                     }/>
                 </ul>
                 <Show when=move || policies.get().is_empty()>
                     <div class="text-center py-12 text-slate-500 italic bg-slate-900/50 rounded-xl border border-slate-800">
                        "No B2B policies configured yet."
                     </div>
                 </Show>
             </div>
        </div>
    }
}
