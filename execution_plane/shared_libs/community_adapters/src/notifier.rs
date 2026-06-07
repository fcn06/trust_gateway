// ─────────────────────────────────────────────────────────────
// LocalDashboardNotifier — Community edition approval notifier.
//
// Publishes approval notifications to `ui.v1.local.events` via
// NATS so the local portal dashboard can display them.
// No Telegram, no external HTTP calls.
// ─────────────────────────────────────────────────────────────

use async_trait::async_trait;
use trust_core::ports::ApprovalNotifier;
use trust_core::ports_dto::ApprovalNotification;

/// Community edition notifier that publishes to the local NATS bus.
pub struct LocalDashboardNotifier {
    nats: async_nats::Client,
}

impl LocalDashboardNotifier {
    pub fn new(nats: async_nats::Client) -> Self {
        Self { nats }
    }
}

#[async_trait]
impl ApprovalNotifier for LocalDashboardNotifier {
    async fn notify_approval_requested(
        &self,
        request: &ApprovalNotification,
    ) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "type": "approval_requested",
            "approval_id": request.approval_id,
            "action_name": request.action_name,
            "tier": request.tier,
            "reason": request.reason,
        });

        let bytes = serde_json::to_vec(&payload)?;
        self.nats
            .publish("ui.v1.local.events".to_string(), bytes.into())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish approval notification: {}", e))?;

        tracing::info!(
            "📢 Approval notification sent to dashboard: {} ({})",
            request.action_name,
            request.approval_id
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration test requires a running NATS server.
    // Unit test verifies the struct can be constructed.
    #[test]
    fn test_notifier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalDashboardNotifier>();
    }
}
