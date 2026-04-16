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
use trust_core::approval::{ApprovalRecord, ApprovalStatus};
use trust_core::audit::AuditEventType;

/// Spawn a background daemon to execute actions asynchronously once they are approved.
pub async fn spawn_execution_daemon(state: Arc<GatewayState>) {
    let js = state.jetstream.clone();
    tokio::spawn(async move {
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
    });
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
            let _ = state.approval_store.mark_execution_failed(
                &approval_id, &format!("Grant issuance failed: {}", e)
            ).await;
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
            
            // Mark as Executed BEFORE auditing (idempotency first)
            if let Err(e) = state.approval_store.mark_executed(&approval_id).await {
                tracing::error!("Failed to mark {} as executed: {}", approval_id, e);
            }

            crate::audit_sink::emit_audit(
                &*state.audit_sink, &tenant_id,
                AuditEventType::ActionSucceeded, "trust_gateway_daemon", &action_id, 
                serde_json::json!({
                    "connector": action_result.connector,
                    "approval_id": approval_id,
                })
            ).await;

            // Publish result to NATS so any waiting agent gets notified
            let result_msg = serde_json::json!({
                "tool_name": action_req.action.name,
                "result": {
                    "content": action_result.output,
                    "is_error": false,
                },
                "action_id": action_id,
                "approval_id": approval_id,
                "status": "succeeded",
            });
            let subject = format!("gateway.v1.action.result.{}", action_id);
            if let Ok(payload) = serde_json::to_vec(&result_msg) {
                let _ = state.nats.publish(subject, payload.into()).await;
            }
        }
        Err(e) => {
            tracing::error!("❌ Daemon execution failed for {}: {}", action_id, e);
            
            // Mark as failed (prevents retry loops)
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
