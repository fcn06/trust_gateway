//! Validation UI Section
//!
//! Displays pending agent tool escalation requests and allows users
//! to approve or deny them.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::types::{EscalationRequest, EnrichedIdentity};

#[component]
pub fn EscalationRequestsSection(
    base_url: String,
    token: String,
    #[allow(unused_variables)] identities: ReadSignal<Vec<EnrichedIdentity>>,
) -> impl IntoView {
    let (requests, set_requests) = signal(Vec::<EscalationRequest>::new());
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(String::new());

    let base_url_sig = StoredValue::new(base_url.clone());
    let token_sig = StoredValue::new(token.clone());

    let load_requests = {
        let base_url_sig = base_url_sig;
        let token_sig = token_sig;
        move || {
            let base = base_url_sig.get_value();
            let tok = token_sig.get_value();
            spawn_local(async move {
                set_loading.set(true);
                set_error_msg.set(String::new());
                match api::get_escalation_requests(&base, tok).await {
                    Ok(list) => set_requests.set(list),
                    Err(e) => set_error_msg.set(format!("Failed to load: {}", e)),
                }
                set_loading.set(false);
            });
        }
    };

    let lr = load_requests.clone();
    Effect::new(move |_| lr());

    view! {
        <div class="space-y-6 max-w-5xl mx-auto">
            <h1 class="text-3xl font-bold bg-gradient-to-r from-amber-400 to-orange-500 bg-clip-text text-transparent mb-2">
                "Validation"
            </h1>

            <div class="space-y-6">
                    <div class="flex items-center justify-between bg-slate-800/50 rounded-xl p-4 border border-slate-700/50">
                        <p class="text-gray-400 text-sm max-w-2xl">
                            "When an AI agent attempts a sensitive action that requires elevated privileges, it needs your explicit approval. "
                            "Pending requests appear below."
                        </p>
                        <button
                            on:click=move |_| load_requests()
                            class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors text-sm font-medium shadow-sm border border-slate-600"
                        >
                            "Refresh"
                        </button>
                    </div>

                    <Show when=move || loading.get()>
                        <div class="text-center py-12">
                            <div class="animate-spin h-10 w-10 border-4 border-blue-500 border-t-transparent rounded-full mx-auto"></div>
                            <p class="text-gray-400 mt-4 font-medium animate-pulse">"Loading escalations..."</p>
                        </div>
                    </Show>

                    <Show when=move || !error_msg.get().is_empty()>
                        <div class="bg-red-900/30 border border-red-500/30 rounded-xl p-4 text-red-300 shadow-sm flex items-start gap-3">
                            <svg class="w-6 h-6 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            <p>{move || error_msg.get()}</p>
                        </div>
                    </Show>

                    <Show when=move || !loading.get() && requests.get().is_empty() && error_msg.get().is_empty()>
                        <div class="bg-slate-800/30 rounded-2xl p-12 text-center border text-slate-500 border-dashed border-slate-700">
                            <div class="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
                                <svg class="w-8 h-8 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            </div>
                            <p class="text-slate-300 text-lg font-medium">"No pending escalations."</p>
                            <p class="text-sm mt-2 max-w-sm mx-auto">"Agent tool calls that require your clearance will appear here when they are intercepted."</p>
                        </div>
                    </Show>

                    <Show when=move || !requests.get().is_empty()>
                        <div class="space-y-4">
                            {move || requests.get().into_iter().map(|req| {
                                let id = req.id.clone();
                                let tool_name = req.tool_name.clone();
                                let user_did = req.user_did.clone();
                                let requester_did = req.requester_did.clone();
                                let display_did = if !requester_did.is_empty() { requester_did } else { user_did };
                                let status = req.status.clone();
                                let created_at = req.created_at.clone();
                                let is_pending = status == "PENDING" || status == "PENDING_PROOF";
                                let arguments = req.arguments.clone();
                                let tier = req.tier.clone();
                                let reason = req.reason.clone();
                                let proof_required = req.proof_required;
                                let action_review = req.action_review.clone();

                                // Extract ActionReview fields for enhanced display
                                let review_title = action_review.as_ref()
                                    .and_then(|r| r.get("normalized_action"))
                                    .and_then(|n| n.get("title"))
                                    .and_then(|t| t.as_str())
                                    .map(|s| s.to_string());
                                let risk_level = action_review.as_ref()
                                    .and_then(|r| r.get("risk_level"))
                                    .and_then(|l| l.as_str())
                                    .map(|s| s.to_string());
                                let system_target = action_review.as_ref()
                                    .and_then(|r| r.get("normalized_action"))
                                    .and_then(|n| n.get("system_target"))
                                    .and_then(|t| t.as_str())
                                    .map(|s| s.to_string());
                                let source_type = action_review.as_ref()
                                    .and_then(|r| r.get("source_type"))
                                    .and_then(|s| s.as_str())
                                    .map(|s| s.to_string());
                                let execution_preview = action_review.as_ref()
                                    .and_then(|r| r.get("execution_preview"))
                                    .and_then(|e| e.as_str())
                                    .map(|s| s.to_string());
                                let policy_reason = action_review.as_ref()
                                    .and_then(|r| r.get("policy_evaluation"))
                                    .and_then(|p| p.get("reason"))
                                    .and_then(|r| r.as_str())
                                    .map(|s| s.to_string());
                                let policy_effect = action_review.as_ref()
                                    .and_then(|r| r.get("policy_evaluation"))
                                    .and_then(|p| p.get("effect"))
                                    .and_then(|e| e.as_str())
                                    .map(|s| s.to_string());
                                let change_preview: Vec<(String, Option<String>, Option<String>)> = action_review.as_ref()
                                    .and_then(|r| r.get("normalized_action"))
                                    .and_then(|n| n.get("change_preview"))
                                    .and_then(|cp| cp.as_array())
                                    .map(|arr| arr.iter().map(|f| {
                                        let label = f.get("label").and_then(|l| l.as_str()).unwrap_or("").to_string();
                                        let before = f.get("before").and_then(|b| b.as_str()).map(|s| s.to_string());
                                        let after = f.get("after").and_then(|a| a.as_str()).map(|s| s.to_string());
                                        (label, before, after)
                                    }).collect())
                                    .unwrap_or_default();

                                let id_approve = id.clone();
                                let id_deny = id.clone();

                                let base_a = base_url_sig.get_value();
                                let tok_a = token_sig.get_value();
                                let base_d = base_url_sig.get_value();
                                let tok_d = token_sig.get_value();

                                // Display title: use ActionReview title if available, else tool_name
                                let display_title = review_title.unwrap_or_else(|| tool_name.clone());

                                // Risk badge styling
                                let risk_badge = risk_level.as_deref().map(|r| match r {
                                    "low" => ("LOW", "bg-green-500/20 text-green-400 border-green-500/30"),
                                    "medium" => ("MEDIUM", "bg-amber-500/20 text-amber-400 border-amber-500/30"),
                                    "high" => ("HIGH", "bg-orange-500/20 text-orange-400 border-orange-500/30"),
                                    "critical" => ("CRITICAL", "bg-red-500/20 text-red-400 border-red-500/30 animate-pulse"),
                                    _ => ("UNKNOWN", "bg-slate-500/20 text-slate-400 border-slate-500/30"),
                                });

                                // Determine tier badge styling
                                let tier_badge = tier.as_deref().map(|t| match t {
                                    "tier0" | "tier0_auto_allow" => ("AUTO", "bg-green-500/20 text-green-400 border-green-500/30"),
                                    "tier1" | "tier1_portal_click" => ("CLICK", "bg-blue-500/20 text-blue-400 border-blue-500/30"),
                                    "tier2" | "tier2_re_authenticate" => ("RE-AUTH", "bg-amber-500/20 text-amber-400 border-amber-500/30"),
                                    "tier3" | "tier3_verified_presentation" => ("VERIFIED", "bg-purple-500/20 text-purple-400 border-purple-500/30"),
                                    _ => ("UNKNOWN", "bg-slate-500/20 text-slate-400 border-slate-500/30"),
                                });

                                view! {
                                    <div class="bg-slate-800 rounded-xl p-5 border border-slate-700 hover:border-blue-500/30 transition-all shadow-lg group">
                                        <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                                            <div class="flex-1 min-w-0">
                                                <div class="flex items-center gap-3 mb-2">
                                                    <div class="w-10 h-10 rounded-lg bg-blue-900/30 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                                                        <span class="text-xl">{
                                                            if proof_required { "🔐" }
                                                            else if system_target.as_deref() == Some("Shopify") { "🛒" }
                                                            else if system_target.as_deref() == Some("Google Calendar") { "📅" }
                                                            else if system_target.as_deref() == Some("Stripe") { "💳" }
                                                            else { "🔧" }
                                                        }</span>
                                                    </div>
                                                    <div>
                                                        <h3 class="text-lg font-bold text-white group-hover:text-blue-400 transition-colors">
                                                            {display_title}
                                                        </h3>
                                                        <div class="flex items-center gap-2 mt-1 flex-wrap">
                                                            <span class=move || format!(
                                                                "px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider {}",
                                                                match status.as_str() {
                                                                    "PENDING" => "bg-amber-500/20 text-amber-400 border border-amber-500/30",
                                                                    "PENDING_PROOF" => "bg-purple-500/20 text-purple-300 border border-purple-500/30 animate-pulse",
                                                                    "PROOF_VERIFIED" => "bg-indigo-500/20 text-indigo-400 border border-indigo-500/30",
                                                                    "APPROVED" => "bg-green-500/20 text-green-400 border border-green-500/30",
                                                                    "DENIED" => "bg-red-500/20 text-red-400 border border-red-500/30",
                                                                    "TIMEOUT" => "bg-slate-500/20 text-slate-400 border border-slate-500/30",
                                                                    _ => "bg-slate-500/20 text-slate-400 border border-slate-500/30",
                                                                }
                                                            )>
                                                                {status.clone()}
                                                            </span>
                                                            {risk_badge.map(|(label, classes)| view! {
                                                                <span class=format!("px-2 py-0.5 rounded text-[10px] font-bold border {}", classes)>
                                                                    {"⚡ "}{label}
                                                                </span>
                                                            })}
                                                            {tier_badge.map(|(label, classes)| view! {
                                                                <span class=format!("px-2 py-0.5 rounded text-[10px] font-bold border {}", classes)>
                                                                    {label}
                                                                </span>
                                                            })}
                                                            {source_type.map(|s| view! {
                                                                <span class="px-2 py-0.5 rounded text-[10px] font-bold border bg-slate-600/20 text-slate-300 border-slate-500/30">
                                                                    {"📡 "}{s}
                                                                </span>
                                                            })}
                                                            <span class="text-xs text-slate-500">"•"</span>
                                                            <span class="text-xs text-slate-500">{created_at.clone()}</span>
                                                            {if is_pending {
                                                                // WS2.2: Approval Card Timer Context (5 min expiry)
                                                                let created_ts = js_sys::Date::new(&created_at.clone().into()).get_time();
                                                                let now = js_sys::Date::now();
                                                                let expires_in_ms = (created_ts + (5.0 * 60.0 * 1000.0)) - now;
                                                                let (timer_text, timer_color) = if expires_in_ms > 0.0 {
                                                                    let mins = (expires_in_ms / 60000.0).floor();
                                                                    let secs = ((expires_in_ms % 60000.0) / 1000.0).floor();
                                                                    let text = format!("Expires in {:02}:{:02}", mins, secs);
                                                                    let color = if mins < 1.0 { "text-red-400 animate-pulse font-bold" } else { "text-amber-500/80 font-medium" };
                                                                    (text, color)
                                                                } else {
                                                                    ("Expired".to_string(), "text-red-500 font-bold")
                                                                };
                                                                
                                                                Some(view! {
                                                                    <span class="text-xs text-slate-500">"•"</span>
                                                                    <span class=format!("text-xs flex items-center gap-1 {}", timer_color)>
                                                                        "⏱️ " {timer_text}
                                                                    </span>
                                                                })
                                                            } else { None }}
                                                        </div>
                                                    </div>
                                                </div>

                                                // Business Diff & Policy section
                                                <div class="mt-4 bg-slate-900/50 rounded-lg p-3 border border-slate-700/50 space-y-3">
                                                    // Business Diff Table (when action_review is present)
                                                    {if !change_preview.is_empty() {
                                                        Some(view! {
                                                            <div>
                                                                <p class="text-xs text-slate-400 font-medium mb-2">"📋 Change Preview"</p>
                                                                <div class="space-y-1">
                                                                    {change_preview.into_iter().map(|(label, before, after)| {
                                                                        view! {
                                                                            <div class="flex items-center text-xs gap-2 py-1 border-b border-slate-700/30 last:border-0">
                                                                                <span class="text-slate-400 w-28 shrink-0 font-medium">{label}</span>
                                                                                {before.map(|b| view! {
                                                                                    <span class="text-red-400/70 line-through mr-1">{b}</span>
                                                                                    <span class="text-slate-500">"→"</span>
                                                                                })}
                                                                                <span class="text-green-300 font-medium ml-1">{after.unwrap_or_default()}</span>
                                                                            </div>
                                                                        }
                                                                    }).collect_view()}
                                                                </div>
                                                            </div>
                                                        })
                                                    } else { None }}

                                                    // Policy evaluation block
                                                    {policy_reason.map(|r| view! {
                                                        <div class="pt-2 border-t border-slate-700/50">
                                                            <p class="text-xs text-slate-400 font-medium mb-1">"🏛️ Policy Reason"</p>
                                                            <p class="text-sm text-amber-300/80">{r}</p>
                                                            {policy_effect.map(|e| view! {
                                                                <p class="text-xs text-slate-500 mt-0.5">{e}</p>
                                                            })}
                                                        </div>
                                                    })}

                                                    // Execution preview
                                                    {execution_preview.map(|e| view! {
                                                        <div class="pt-2 border-t border-slate-700/50">
                                                            <div class="flex items-center gap-2">
                                                                <span class="text-blue-400">"⚡"</span>
                                                                <p class="text-xs text-blue-300/80">{e}</p>
                                                            </div>
                                                        </div>
                                                    })}

                                                    // Proof required indicator
                                                    {if proof_required {
                                                        Some(view! {
                                                            <div class="pt-2 border-t border-slate-700/50">
                                                                <div class="flex items-center gap-2">
                                                                    <span class="text-purple-400">"🔐"</span>
                                                                    <p class="text-xs text-purple-300 font-medium">"Verified approver required — credential presentation needed"</p>
                                                                </div>
                                                            </div>
                                                        })
                                                    } else { None }}

                                                    // Originating DID (collapsed)
                                                    <div class="pt-2 border-t border-slate-700/50">
                                                        <p class="text-xs text-slate-500 font-medium mb-1">"Requester:"</p>
                                                        <p class="font-mono text-[10px] text-slate-400 break-all">
                                                            {display_did.clone()}
                                                        </p>
                                                    </div>

                                                    // Raw arguments (collapsible technical details)
                                                    {
                                                        let args_for_view = arguments.clone();
                                                        view! {
                                                            <Show when=move || args_for_view.is_some()>
                                                                <details class="pt-2 border-t border-slate-700/50">
                                                                    <summary class="text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">"▸ Technical Details (raw arguments)"</summary>
                                                                    <pre class="font-mono text-[10px] text-green-300/70 break-all whitespace-pre-wrap mt-2">
                                                                        {
                                                                            let a = arguments.clone();
                                                                            serde_json::to_string_pretty(&a.unwrap()).unwrap_or_default()
                                                                        }
                                                                    </pre>
                                                                </details>
                                                            </Show>
                                                        }
                                                    }
                                                </div>
                                            </div>

                                            {if is_pending {
                                                let id_a = id_approve.clone();
                                                let id_a2 = id_approve.clone();
                                                let id_d = id_deny.clone();
                                                let id_d2 = id_deny.clone();
                                                view! {
                                                    <div class="flex w-full md:w-auto md:flex-col gap-2 shrink-0">
                                                        <button
                                                            on:click=move |_| {
                                                                let base = base_a.clone();
                                                                let tok = tok_a.clone();
                                                                let id = id_a.clone();
                                                                let id2 = id_a2.clone();
                                                                spawn_local(async move {
                                                                    if let Ok(()) = api::approve_escalation_request(&base, id, tok).await {
                                                                        set_requests.update(|reqs| {
                                                                            if let Some(r) = reqs.iter_mut().find(|r| r.id == id2) {
                                                                                r.status = "APPROVED".to_string();
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }
                                                            class="flex-1 md:flex-none px-6 py-2.5 bg-green-600/20 hover:bg-green-500 text-green-400 hover:text-white rounded-lg transition-all text-sm font-bold border border-green-500/30 hover:border-green-500 hover:shadow-lg hover:shadow-green-500/20 flex items-center justify-center gap-2"
                                                        >
                                                            <span>"✅"</span> "Approve"
                                                        </button>
                                                        <button
                                                            on:click=move |_| {
                                                                let base = base_d.clone();
                                                                let tok = tok_d.clone();
                                                                let id = id_d.clone();
                                                                let id2 = id_d2.clone();
                                                                spawn_local(async move {
                                                                    if let Ok(()) = api::deny_escalation_request(&base, id, tok).await {
                                                                        set_requests.update(|reqs| {
                                                                            if let Some(r) = reqs.iter_mut().find(|r| r.id == id2) {
                                                                                r.status = "DENIED".to_string();
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }
                                                            class="flex-1 md:flex-none px-6 py-2.5 bg-red-600/20 hover:bg-red-500 text-red-400 hover:text-white rounded-lg transition-all text-sm font-bold border border-red-500/30 hover:border-red-500 hover:shadow-lg hover:shadow-red-500/20 flex items-center justify-center gap-2"
                                                        >
                                                            <span>"🚫"</span> "Deny"
                                                        </button>
                                                    </div>
                                                }.into_any()
                                            } else {
                                                view! { <span></span> }.into_any()
                                            }}
                                        </div>
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    </Show>
            </div>
        </div>
    }
}
