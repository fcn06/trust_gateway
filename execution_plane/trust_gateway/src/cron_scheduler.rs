// ─────────────────────────────────────────────────────────────
// Cron Scheduler — Event-driven temporal orchestrator
//
// Periodically checks the ToolRegistry for skills that define
// a `cron` schedule (e.g., "0 9 * * 1"). When a cron triggers,
// it constructs a ProposedAction and injects it into the
// internal processing pipeline via NATS.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use std::str::FromStr;
use cron::Schedule;
use chrono::Utc;
use trust_core::action::{ActionRequest, ActionDescriptor, OperationKind};
use trust_core::actor::{ActorContext, SourceContext, AuthLevel};

use crate::gateway::GatewayState;

pub async fn run_cron_scheduler(state: Arc<GatewayState>) {
    tracing::info!("⏱️ Cron Scheduler starting...");

    // Check schedules every 60 seconds (aligned to the minute boundary)
    loop {
        // Sleep until the start of the next minute
        let now = Utc::now();
        let seconds_until_next_minute = 60 - now.timestamp() % 60;
        tokio::time::sleep(std::time::Duration::from_secs(seconds_until_next_minute as u64)).await;

        let check_time = Utc::now();
        tracing::debug!("⏱️ Evaluating cron schedules at {}", check_time);

        if let Some(ref registry) = state.tool_registry {
            // Ensure registry is up to date
            registry.refresh_if_stale(&state.http_client, &state.connectors.host_url, &state.connectors.vp_mcp_url).await;

            let tools = registry.all_tools().await;
            for (tool_name, entry) in tools {
                if let Some(cron_expr) = &entry.cron {
                    // Try to parse the schedule
                    match Schedule::from_str(cron_expr) {
                        Ok(schedule) => {
                            // Check if this schedule includes the current minute
                            // Since we wake up at the top of the minute, we check if there's
                            // an event that falls exactly on this minute.
                            let mut upcoming = schedule.upcoming(Utc);
                            if let Some(next_event) = upcoming.next() {
                                // If the next event is within the current minute window
                                let diff = next_event.timestamp() - check_time.timestamp();
                                if diff.abs() < 60 {
                                    tracing::info!("⏰ Cron triggered for tool: {}", tool_name);
                                    dispatch_cron_action(&state, &tool_name, &entry).await;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ Invalid cron expression '{}' for tool '{}': {}", cron_expr, tool_name, e);
                        }
                    }
                }
            }
        }
    }
}

async fn dispatch_cron_action(state: &Arc<GatewayState>, tool_name: &str, _entry: &crate::router::ToolRegistryEntry) {
    let action_id = uuid::Uuid::new_v4().to_string();
    
    // Create a system tenant context or rely on a specific service account.
    // For cron skills, they operate under the 'system' tenant unless specified.
    let tenant_id = "system-cron-tenant".to_string();

    let action_req = ActionRequest {
        action_id: action_id.clone(),
        tenant_id: tenant_id.clone(),
        actor: ActorContext {
            owner_did: "system".to_string(),
            requester_did: "system:cron".to_string(),
            user_did: None,
            session_jti: action_id.clone(),
            auth_level: AuthLevel::Session,
        },
        source: SourceContext {
            source_type: "cron_scheduler".to_string(),
            name: Some("Cron Scheduler".to_string()),
            instance_id: None,
        },
        action: ActionDescriptor {
            name: tool_name.to_string(),
            category: "cron".to_string(),
            resource: None,
            operation: OperationKind::Create,
            amount: None,
            arguments: serde_json::json!({}),
            tags: vec!["cron".to_string()],
        },
    };

    match crate::gateway::process_action(state.clone(), action_req).await {
        Ok(_) => tracing::info!("✅ Dispatched and executed cron action {}", tool_name),
        Err(e) => tracing::error!("❌ Failed to process cron action: {}", e),
    }
}
