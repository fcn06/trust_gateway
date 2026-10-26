pub use crate::traits::{ApprovalNotifier, ApprovalRequest, EngineError};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use trust_sdk::model::ProposedAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub action_id: String,
    pub tenant_id: String,
    pub status: ApprovalStatus,
    pub proposed_action: ProposedAction,
    pub reason: String,
    pub requested_at: i64,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage_dossier: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_rule: Option<serde_json::Value>,
}

pub struct NoopApprovalNotifier;

#[async_trait]
impl ApprovalNotifier for NoopApprovalNotifier {
    async fn notify_pending(&self, _req: &ApprovalRequest) -> Result<(), EngineError> {
        Ok(())
    }
}

pub struct WebhookApprovalNotifier {
    webhook_url: String,
    signing_key: SigningKey,
    step_up_base_url: String,
    client: reqwest::Client,
}

impl WebhookApprovalNotifier {
    pub fn new(
        webhook_url: impl Into<String>,
        signing_key: SigningKey,
        step_up_base_url: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            webhook_url: webhook_url.into(),
            signing_key,
            step_up_base_url: step_up_base_url.into(),
            client,
        }
    }
}

#[async_trait]
impl ApprovalNotifier for WebhookApprovalNotifier {
    async fn notify_pending(&self, req: &ApprovalRequest) -> Result<(), EngineError> {
        let mut final_req = req.clone();
        if !self.step_up_base_url.is_empty() && !final_req.step_up_url.starts_with("http") {
            let base = self.step_up_base_url.trim_end_matches('/');
            let path = final_req.step_up_url.trim_start_matches('/');
            final_req.step_up_url = format!("{base}/{path}");
        }

        let payload_bytes = serde_json::to_vec(&final_req)
            .map_err(|e| EngineError::Internal(format!("Serialization error: {e}")))?;

        let sig = self.signing_key.sign(&payload_bytes);
        let sig_hex = hex::encode(sig.to_bytes());

        let client = self.client.clone();
        let url = self.webhook_url.clone();

        tokio::spawn(async move {
            let res = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Lianxi-Webhook-Signature", sig_hex)
                .body(payload_bytes)
                .send()
                .await;

            if let Err(e) = res {
                tracing::warn!("Webhook approval notification to {} failed: {}", url, e);
            }
        });

        Ok(())
    }
}

pub struct ApprovalManager {
    records: Arc<RwLock<HashMap<String, ApprovalRecord>>>,
    notifier: Arc<dyn ApprovalNotifier>,
    ttl_secs: i64,
}

impl ApprovalManager {
    pub fn new(notifier: Arc<dyn ApprovalNotifier>) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            notifier,
            ttl_secs: 3600, // 1 hour default TTL
        }
    }

    pub fn with_ttl(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    pub async fn create_request(
        &self,
        action: ProposedAction,
        reason: String,
    ) -> Result<ApprovalRecord, EngineError> {
        let approval_id = format!("appr_{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp();
        let record = ApprovalRecord {
            approval_id: approval_id.clone(),
            action_id: action.action_id.clone(),
            tenant_id: action.tenant_id.clone(),
            status: ApprovalStatus::Pending,
            proposed_action: action,
            reason,
            requested_at: now,
            expires_at: now + self.ttl_secs,
            resolved_by: None,
            resolved_at: None,
            triage_dossier: None,
            candidate_rule: None,
        };

        {
            let mut lock = self.records.write().await;
            lock.insert(approval_id.clone(), record.clone());
        }

        let _ = self.notifier.notify_approval_requested(&record).await;
        Ok(record)
    }

    pub async fn create_enriched_request(
        &self,
        action: ProposedAction,
        reason: String,
        triage_dossier: Option<serde_json::Value>,
        candidate_rule: Option<serde_json::Value>,
    ) -> Result<ApprovalRecord, EngineError> {
        let approval_id = format!("appr_{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp();
        let record = ApprovalRecord {
            approval_id: approval_id.clone(),
            action_id: action.action_id.clone(),
            tenant_id: action.tenant_id.clone(),
            status: ApprovalStatus::Pending,
            proposed_action: action,
            reason,
            requested_at: now,
            expires_at: now + self.ttl_secs,
            resolved_by: None,
            resolved_at: None,
            triage_dossier,
            candidate_rule,
        };

        {
            let mut lock = self.records.write().await;
            lock.insert(approval_id.clone(), record.clone());
        }

        let _ = self.notifier.notify_approval_requested(&record).await;
        Ok(record)
    }

    pub async fn resolve(
        &self,
        approval_id: &str,
        approved: bool,
        resolved_by: String,
    ) -> Result<ApprovalRecord, EngineError> {
        let mut lock = self.records.write().await;
        let record = lock.get_mut(approval_id).ok_or_else(|| {
            EngineError::Internal(format!("Approval record not found: {approval_id}"))
        })?;

        if record.status != ApprovalStatus::Pending {
            return Err(EngineError::Internal(format!(
                "Approval record is already terminal ({:?})",
                record.status
            )));
        }

        let now = chrono::Utc::now().timestamp();
        if now > record.expires_at {
            record.status = ApprovalStatus::Expired;
            return Err(EngineError::Internal(
                "Approval record has expired".to_string(),
            ));
        }

        record.status = if approved {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };
        record.resolved_by = Some(resolved_by);
        record.resolved_at = Some(now);

        let updated = record.clone();
        drop(lock);

        let _ = self.notifier.notify_approval_resolved(&updated).await;
        Ok(updated)
    }

    pub async fn get(&self, approval_id: &str) -> Option<ApprovalRecord> {
        let lock = self.records.read().await;
        lock.get(approval_id).cloned()
    }

    pub async fn sweep_expired(&self) -> usize {
        let mut lock = self.records.write().await;
        let now = chrono::Utc::now().timestamp();
        let mut count = 0;
        for record in lock.values_mut() {
            if record.status == ApprovalStatus::Pending && now > record.expires_at {
                record.status = ApprovalStatus::Expired;
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_approval_lifecycle_and_expiry() {
        let mgr = ApprovalManager::new(Arc::new(NoopApprovalNotifier)).with_ttl(1);
        let action = ProposedAction {
            action_id: "act_101".to_string(),
            tool_name: "stripe.charge".to_string(),
            ..Default::default()
        };

        let req = mgr
            .create_request(action, "High cost".to_string())
            .await
            .unwrap();
        assert_eq!(req.status, ApprovalStatus::Pending);

        // Resolve approve
        let resolved = mgr
            .resolve(&req.approval_id, true, "admin".to_string())
            .await
            .unwrap();
        assert_eq!(resolved.status, ApprovalStatus::Approved);
        assert_eq!(resolved.resolved_by.as_deref(), Some("admin"));
    }
}
