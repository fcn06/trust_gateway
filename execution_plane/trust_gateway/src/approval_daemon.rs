// ─────────────────────────────────────────────────────────────
// Approval Daemon — Background Supervisor for Async Execution
//
// Watches the `approval_records` JetStream KV bucket for state
// changes. When a record transitions to `Approved`, the daemon
// issues an ExecutionGrant, dispatches the connector, and marks
// the record as `Executed` or `ExecutionFailed`.
//
// Idempotency: The daemon only acts on records with status
// `Approved`. Once dispatched, the record is immediately
// transitioned to a terminal state, preventing double-execution
// on gateway restart.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use crate::gateway::GatewayState;
use trust_core::approval::{ApprovalRecord, ApprovalResult, ApprovalStatus};
use trust_core::audit::AuditEventType;

/// Spawn a NATS listener for approval decisions from the Host portal.
///
/// The Host publishes to `gateway.v1.approval.decision` when a user
/// approves or denies an escalation request in the portal. This listener
/// updates the gateway's `approval_records` KV, which triggers the
/// KV watcher in `spawn_execution_daemon` to execute the action.
pub async fn run_decision_listener(state: Arc<GatewayState>) {
    let nc = state.nats.clone();

        let subject = "gateway.v1.approval.decision";
        let mut sub = match nc.subscribe(subject.to_string()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("❌ Failed to subscribe to {}: {}", subject, e);
                return;
            }
        };
        tracing::info!("📬 Approval decision listener subscribed to {}", subject);

        use futures::StreamExt;
        while let Some(msg) = sub.next().await {
            let payload: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("⚠️ Invalid approval decision payload: {}", e);
                    continue;
                }
            };

            let approval_id = match payload["approval_id"].as_str() {
                Some(id) => id.to_string(),
                None => {
                    tracing::warn!("⚠️ Missing approval_id in decision payload");
                    continue;
                }
            };

            let decision = payload["decision"].as_str().unwrap_or("unknown");
            let resolved_by = payload["resolved_by"].as_str().unwrap_or("portal_user").to_string();

            let result = ApprovalResult {
                resolved_by: resolved_by.clone(),
                resolution_method: "portal_click".to_string(),
                notes: None,
                resolved_at: chrono::Utc::now(),
            };

            match decision {
                "approve" => {
                    match state.approval_store.mark_approved(&approval_id, result).await {
                        Ok(_) => {
                            tracing::info!(
                                "✅ Approval {} marked as Approved via NATS (by: {})",
                                approval_id, resolved_by
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "⚠️ Failed to mark approval {} as Approved: {}",
                                approval_id, e
                            );
                        }
                    }
                }
                "deny" => {
                    match state.approval_store.mark_denied(&approval_id, result).await {
                        Ok(_) => {
                            tracing::info!(
                                "🚫 Approval {} marked as Denied via NATS (by: {})",
                                approval_id, resolved_by
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "⚠️ Failed to mark approval {} as Denied: {}",
                                approval_id, e
                            );
                        }
                    }
                }
                other => {
                    tracing::warn!("⚠️ Unknown decision '{}' for approval {}", other, approval_id);
                }
            }
        }

        tracing::warn!("⚠️ Approval decision NATS listener ended unexpectedly");
}

/// Spawn a background daemon to execute actions asynchronously once they are approved.
pub async fn run_execution_daemon(state: Arc<GatewayState>) {
    let js = state.jetstream.clone();
    tracing::info!("✅ Supervisor daemon starting — watching for action approvals...");

        // Try to get the KV store for approvals (retries until available)
        let kv = loop {
            match js.get_key_value("approval_records").await {
                Ok(store) => break store,
                Err(e) => {
                    tracing::warn!("Supervisor waiting for approval_records KV: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        };

        // On startup, sweep for any Approved records that weren't executed
        // (handles crash recovery — records approved while daemon was down)
        sweep_pending_approvals(&state).await;

        // Watch for all KV changes going forward
        let mut watcher = match kv.watch(">").await {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("❌ Could not watch KV: {}", e);
                return;
            }
        };

        use futures::StreamExt;
        while let Some(Ok(entry)) = watcher.next().await {
            if entry.operation == async_nats::jetstream::kv::Operation::Put {
                if let Ok(record) = serde_json::from_slice::<ApprovalRecord>(&entry.value) {
                    if record.status == ApprovalStatus::Approved {
                        tracing::info!("🚀 Daemon detected Approved action: {}", record.action_id);
                        
                        let state = state.clone();
                        tokio::spawn(async move {
                            execute_approved_action(state, record).await;
                        });
                    }
                }
            }
        }

        tracing::warn!("⚠️ Supervisor daemon KV watcher ended unexpectedly");
}

/// On startup, scan for any records stuck in `Approved` state
/// (these were approved while the daemon was down or crashed mid-dispatch).
async fn sweep_pending_approvals(state: &Arc<GatewayState>) {
    let kv = match state.jetstream.get_key_value("approval_records").await {
        Ok(store) => store,
        Err(_) => return,
    };

    use futures::StreamExt;
    let mut keys = match kv.keys().await {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut recovery_count = 0u32;
    let mut keys_vec = Vec::new();
    while let Some(Ok(key)) = keys.next().await {
        keys_vec.push(key);
    }

    for key in keys_vec {
        if let Ok(Some(entry)) = kv.get(&key).await {
            if let Ok(record) = serde_json::from_slice::<ApprovalRecord>(&entry) {
                if record.status == ApprovalStatus::Approved {
                    tracing::info!(
                        "🔄 Recovery: found orphaned Approved record {} (action: {})",
                        record.approval_id, record.action_id
                    );
                    let state = state.clone();
                    tokio::spawn(async move {
                        execute_approved_action(state, record).await;
                    });
                    recovery_count += 1;
                }
            }
        }
    }

    if recovery_count > 0 {
        tracing::info!("🔄 Recovery sweep: dispatching {} orphaned approved actions", recovery_count);
    } else {
        tracing::info!("✅ Recovery sweep: no orphaned approvals found");
    }
}

async fn execute_approved_action(state: Arc<GatewayState>, record: ApprovalRecord) {
    let approval_id = record.approval_id.clone();
    let action_id = record.action_id.clone();
    let tenant_id = record.tenant_id.clone();
    let action_req = record.action_request.clone();

    // WS3.3: Pre-check — re-read from store to confirm still in Approved state.
    // Prevents double-execution when multiple daemon instances or KV watcher
    // replays trigger on the same record.
    match state.approval_store.get(&approval_id).await {
        Ok(Some(current)) => {
            if current.status != trust_core::approval::ApprovalStatus::Approved {
                tracing::info!(
                    "⏭️ Daemon skipping {} — status already changed to {}",
                    approval_id, current.status
                );
                return;
            }
        }
        Ok(None) => {
            tracing::warn!("⚠️ Daemon: approval {} not found — skipping", approval_id);
            return;
        }
        Err(e) => {
            tracing::error!("❌ Daemon: failed to re-read approval {}: {}", approval_id, e);
            return;
        }
    }

    // Determine clearance from approval tier
    let clearance = match record.tier {
        trust_core::approval::ApprovalTier::Tier2ReAuthenticate => {
            trust_core::grant::GrantClearance::ElevatedApproval
        }
        trust_core::approval::ApprovalTier::Tier3VerifiedPresentation => {
            trust_core::grant::GrantClearance::ProofVerified
        }
        _ => trust_core::grant::GrantClearance::HumanApproved,
    };
        
    let grant = match state.grant_issuer.issue_execution_grant(
        &action_req, clearance, std::time::Duration::from_secs(30)
    ) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Daemon failed to issue grant for {}: {}", action_id, e);
            if let Err(mark_err) = state.approval_store.mark_execution_failed(
                &approval_id, &format!("Grant issuance failed: {}", e)
            ).await {
                tracing::error!("Failed to mark {} as execution_failed: {}", approval_id, mark_err);
            }
            return;
        }
    };
    
    // Audit: grant issued
    crate::audit_sink::emit_audit(
        &*state.audit_sink, &tenant_id,
        AuditEventType::GrantIssued, "trust_gateway_daemon", &action_id, 
        serde_json::json!({
            "approval_id": approval_id,
            "grant_id": grant.claims.grant_id,
            "clearance": format!("{:?}", clearance),
        })
    ).await;
                                    
    // Perform connector dispatch
    match crate::router::dispatch_to_connector(&state, &action_req, &grant).await {
        Ok(action_result) => {
            tracing::info!("✅ Daemon completed execution for {} (connector: {})", action_id, action_result.connector);
            
            // Mark as Executed (CAS-protected — prevents double-execution)
            match state.approval_store.mark_executed(&approval_id).await {
                Ok(_) => {},
                Err(trust_core::errors::StoreError::InvalidTransition { .. }) => {
                    tracing::warn!(
                        "⏭️ Approval {} already transitioned — skipping post-execution audit",
                        approval_id
                    );
                    return;
                }
                Err(trust_core::errors::StoreError::ConcurrencyConflict { .. }) => {
                    tracing::warn!(
                        "⚠️ CAS conflict marking {} as executed — another instance handled it",
                        approval_id
                    );
                    return;
                }
                Err(e) => {
                    tracing::error!("Failed to mark {} as executed: {}", approval_id, e);
                }
            }

            crate::audit_sink::emit_audit(
                &*state.audit_sink, &tenant_id,
                AuditEventType::ActionSucceeded, "trust_gateway_daemon", &action_id, 
                serde_json::json!({
                    "connector": action_result.connector,
                    "approval_id": approval_id,
                })
            ).await;

            // Publish result to NATS so the Host can notify the user
            let result_msg = serde_json::json!({
                "tool_name": action_req.action.name,
                "result": {
                    "content": action_result.output,
                    "is_error": false,
                },
                "action_id": action_id,
                "approval_id": approval_id,
                "status": "succeeded",
                "owner_did": action_req.actor.owner_did,
                "requester_did": action_req.actor.requester_did,
            });
            // Notify both the generic result channel and the Host notification channel
            let subject = format!("gateway.v1.action.result.{}", action_id);
            if let Ok(payload) = serde_json::to_vec(&result_msg) {
                let _ = state.nats.publish(subject, payload.clone().into()).await;
                let _ = state.nats.publish(
                    "host.v1.escalation.result".to_string(),
                    payload.into(),
                ).await;
                tracing::info!(
                    "📩 Published execution result to host.v1.escalation.result (tool: {}, owner: {})",
                    action_req.action.name, action_req.actor.owner_did
                );
            }
        }
        Err(e) => {
            tracing::error!("❌ Daemon execution failed for {}: {}", action_id, e);
            
            // Mark as failed (CAS-protected — prevents overwriting terminal states)
            if let Err(mark_err) = state.approval_store.mark_execution_failed(
                &approval_id, &format!("{}", e)
            ).await {
                tracing::error!("Failed to mark {} as execution_failed: {}", approval_id, mark_err);
            }

            crate::audit_sink::emit_audit(
                &*state.audit_sink, &tenant_id,
                AuditEventType::ActionFailed, "trust_gateway_daemon", &action_id, 
                serde_json::json!({
                    "error": format!("{}", e),
                    "approval_id": approval_id,
                })
            ).await;
        }
    }
}
