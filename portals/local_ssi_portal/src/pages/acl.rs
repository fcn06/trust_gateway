//! ACL Manager page component.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::ConnectionPolicy;

#[component]
pub fn AclManager(
    base_url: String, 
    username: String, 
    token: String, 
    policies: ReadSignal<Vec<ConnectionPolicy>>, 
    set_policies: WriteSignal<Vec<ConnectionPolicy>>
) -> impl IntoView {
    let (trigger, set_trigger) = signal(0);
    let token = store_value(token);
    let _u = username.clone();
    
    let base_url = store_value(base_url);
    Effect::new(move |_| {
        let _ = trigger.get();
        let tt = token.get_value();
        let ab = base_url.get_value();
        spawn_local(async move {
            if let Ok(list) = api::get_policies(&ab, tt).await {
                set_policies.set(list);
            }
        });
    });
    
    let (did_input, set_did) = signal(String::new());
    let (alias_input, set_alias) = signal(String::new());
    
    let (enrich_did, set_enrich_did) = signal(Option::<String>::None);
    let (enrich_alias, set_enrich_alias) = signal(String::new());
    let (enrich_permissions, set_enrich_permissions) = signal(Vec::<String>::new());

    let on_add = move |_| {
         let d = did_input.get();
         let a = alias_input.get();
         let _owner = username.clone();
         if d.is_empty() { return; }
         
         let policy = ConnectionPolicy {
             did: d,
             alias: a,
             permissions: vec!["Chat".to_string()],
             status: "Active".to_string(),
             created_at: js_sys::Date::now() as i64 / 1000,
         };
         
         let tt = token.get_value();
         let ab = base_url.get_value();
         spawn_local(async move {
             match api::update_policy(&ab, policy, tt).await {
                 Ok(_) => {
                     set_trigger.update(|n| *n += 1);
                     set_did.set(String::new());
                     set_alias.set(String::new());
                 },
                 Err(e) => log::error!("ACL update failed: {}", e),
             }
         });
    };

    view! {
        <div class="space-y-6 text-white bg-slate-800 p-6 rounded-2xl border border-slate-700">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">"Approved Contacts"</h2>
                <button
                    on:click=move |_| set_trigger.update(|n| *n += 1)
                    class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all shadow-sm border border-slate-600">
                    "Refresh"
                </button>
            </div>
            
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
                <input type="text" placeholder="Contact Identity (e.g. username@domain)" class="bg-slate-900 border border-slate-700 rounded p-2 text-sm"
                    prop:value=move || did_input.get()
                    on:input=move |ev| set_did.set(event_target_value(&ev)) />
                <input type="text" placeholder="Alias" class="bg-slate-900 border border-slate-700 rounded p-2 text-sm"
                    prop:value=move || alias_input.get()
                    on:input=move |ev| set_alias.set(event_target_value(&ev)) />
                <button on:click=on_add class="bg-green-600 hover:bg-green-500 rounded font-bold py-2 sm:col-span-2 lg:col-span-1">"Authorize Contact"</button>
            </div>
            
             <ul class="space-y-2">
                 <For each=move || policies.get() key=|p| format!("{}-{}-{:?}-{}", p.did, p.alias, p.permissions, p.status) children=move |p| {
                     let did = p.did.clone();
                     let p_clone = p.clone();
                     view! {
                         <li class="bg-slate-900 p-3 rounded border border-slate-700 flex justify-between items-center">
                             <div class="flex flex-col">
                                 <span class="font-bold cursor-help group relative">{p_clone.alias.clone()}
                                    <div class="invisible group-hover:visible absolute left-0 bottom-full mb-1 p-2 bg-slate-800 border border-slate-600 rounded shadow-xl text-xs z-50 whitespace-nowrap font-normal">
                                        {p_clone.did.clone()}
                                    </div>
                                </span>
                                 <span class="text-[10px] text-slate-400">"Permissions: " {p_clone.permissions.join(", ")}</span>
                             </div>
                             <div class="flex items-center gap-3">
                                 <span class="text-green-400 text-xs font-bold">{p_clone.status.clone()}</span>
                                 <button 
                                     on:click=move |_| {
                                         let d = did.clone();
                                         let a = p_clone.alias.clone();
                                         let perms = p_clone.permissions.clone();
                                         set_enrich_did.set(Some(d));
                                         set_enrich_alias.set(a);
                                         set_enrich_permissions.set(perms);
                                     }
                                     class="px-3 py-1 bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white rounded border border-blue-500/30 transition-all text-xs font-bold"
                                 >
                                     "Enrich"
                                 </button>
                             </div>
                         </li>
                     }
                 }/>
             </ul>
              <Show when=move || policies.get().is_empty()>
                  <div class="text-center py-4 text-slate-500 italic">"No policies found"</div>
              </Show>

              <Show when=move || enrich_did.get().is_some()>
                  <div class="mt-8 p-6 bg-slate-900 rounded-2xl border border-blue-500/50 space-y-4 animate-in zoom-in duration-200">
                      <div class="flex justify-between items-center">
                          <h3 class="text-lg font-bold text-blue-300">"Enrich Metadata"</h3>
                          <button on:click=move |_| set_enrich_did.set(None) class="text-slate-500 hover:text-white text-xl">"×"</button>
                      </div>

                      <div class="p-3 bg-slate-800 rounded border border-slate-700">
                          <p class="text-[10px] text-slate-500 uppercase font-bold">"Identity Identifier"</p>
                          <p class="text-xs font-mono text-blue-300 break-all">{move || enrich_did.get().unwrap_or_default()}</p>
                      </div>

                      <div>
                          <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Alias"</label>
                          <input 
                              type="text" 
                              class="w-full bg-slate-800 border border-slate-700 rounded p-2 text-sm"
                              prop:value=move || enrich_alias.get()
                              on:input=move |ev| set_enrich_alias.set(event_target_value(&ev))
                          />
                      </div>

                      <div>
                          <label class="block text-xs font-bold text-slate-400 mb-1 uppercase">"Permissions"</label>
                          <div class="flex flex-wrap gap-2">
                              {["Chat", "Discovery", "Payment", "Appointment"].into_iter().map(|perm| {
                                  let p_str = perm.to_string();
                                  let p_toggle = p_str.clone();
                                  view! {
                                      <button
                                          on:click=move |_| {
                                              let mut current = enrich_permissions.get();
                                              if current.contains(&p_toggle) {
                                                  current.retain(|x| x != &p_toggle);
                                              } else {
                                                  current.push(p_toggle.clone());
                                              }
                                              set_enrich_permissions.set(current);
                                          }
                                          class=move || format!(
                                              "px-3 py-1 rounded text-xs font-bold transition-all {}",
                                              if enrich_permissions.get().contains(&p_str) {
                                                  "bg-blue-600 text-white"
                                              } else {
                                                  "bg-slate-800 text-slate-500 hover:bg-slate-700"
                                              }
                                          )
                                      >
                                          {p_str.clone()}
                                      </button>
                                  }
                              }).collect_view()}
                          </div>
                      </div>

                      <button 
                          on:click=move |_| {
                              let did = match enrich_did.get() {
                                  Some(d) => d,
                                  None => return,
                              };
                              
                              let policy = ConnectionPolicy {
                                   did,
                                   alias: enrich_alias.get(),
                                   permissions: enrich_permissions.get(),
                                   status: "Active".to_string(),
                                   created_at: js_sys::Date::now() as i64 / 1000,
                              };
                              
                              let tt = token.get_value();
                              let ab = base_url.get_value();
                              spawn_local(async move {
                                  match api::update_policy(&ab, policy, tt).await {
                                      Ok(_) => {
                                          set_trigger.update(|n| *n += 1);
                                          set_enrich_did.set(None);
                                      },
                                      Err(e) => log::error!("Enrichment save failed: {}", e),
                                  }
                              });
                          }
                          class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 py-2 rounded font-bold transition-all shadow-lg shadow-blue-600/20"
                      >
                          "Save Changes"
                      </button>
                  </div>
              </Show>
        </div>
    }
}
