use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trust_sdk::manifest::{RemoteSkillPublication, SkillManifest};
use trust_sdk::model::{
    AuditEvent, EconomicCap, EconomicClaim, ExecutionResult, ProposedAction, Tier, TrustEnvelope,
};
use trust_sdk::receipts::ExecutionReceipt;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Unauthorized tenant access: '{0}' (public edition is hard mono-tenant 'default')")]
    UnauthorizedTenant(String),

    #[error("Call-chain violation: {0}")]
    CallChainViolation(String),

    #[error("Skill not found: {0}")]
    SkillNotFound(String),

    #[error("Skill validation failed: {0}")]
    SkillValidation(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Human approval required (Action ID: {action_id}, Approval ID: {approval_id}, Reason: {reason})")]
    ApprovalRequired {
        action_id: String,
        approval_id: String,
        reason: String,
    },

    #[error("Action was denied: {0}")]
    ActionDenied(String),

    #[error("Lineage violation on argument '{argument}': expected sources {expected_sources:?}")]
    LineageViolation {
        argument: String,
        expected_sources: Vec<String>,
    },

    #[error("Replay detected: nonce '{0}' has already been consumed")]
    ReplayDetected(String),

    #[error("Egress payload too large: {size} bytes exceeds maximum allowed {max} bytes")]
    EgressPayloadTooLarge { size: usize, max: usize },

    #[error("Execution dispatch failed: {0}")]
    DispatchError(String),

    #[error("Economic settlement failure: {0}")]
    SettlementError(String),

    #[error("Storage/Database error: {0}")]
    StorageError(String),

    #[error("Internal engine error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub action_id: String,
    pub tenant_id: String,
    pub tool_id: String,
    pub input_hash: String,
    pub reason: String,
    pub step_up_url: String,
}

#[async_trait]
pub trait ApprovalNotifier: Send + Sync {
    async fn notify_pending(&self, req: &ApprovalRequest) -> Result<(), EngineError>;
    async fn notify_approval_requested(
        &self,
        record: &crate::approval::ApprovalRecord,
    ) -> Result<(), EngineError> {
        let req = ApprovalRequest {
            action_id: record.action_id.clone(),
            tenant_id: record.tenant_id.clone(),
            tool_id: record.proposed_action.tool_name.clone(),
            input_hash: trust_sdk::canonical::canonical_hash(&record.proposed_action.arguments),
            reason: record.reason.clone(),
            step_up_url: format!("/v1/approvals/{}/decision", record.approval_id),
        };
        self.notify_pending(&req).await
    }
    async fn notify_approval_resolved(
        &self,
        _record: &crate::approval::ApprovalRecord,
    ) -> Result<(), EngineError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintDecision {
    Allow,
    DowngradeToHumanApproval {
        reason: String,
    },
    DenyLineageViolation {
        argument: String,
        expected_sources: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationDecision {
    pub tier_override: Option<Tier>,
    pub budget_clamp: Option<EconomicCap>,
    pub force_isolated_runtime: bool,
    pub reason: String,
}

impl Default for ReputationDecision {
    fn default() -> Self {
        Self {
            tier_override: None,
            budget_clamp: None,
            force_isolated_runtime: false,
            reason: "Default no-op reputation".to_string(),
        }
    }
}

#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn consume_nonce(
        &self,
        tenant_id: &str,
        jti: &str,
        ttl_secs: u64,
    ) -> Result<(), EngineError>;
}

#[async_trait]
pub trait SkillRegistry: Send + Sync {
    async fn list_skills(
        &self,
        tenant_id: &str,
        bundle: Option<&str>,
    ) -> Result<Vec<SkillManifest>, EngineError>;
    async fn get_skill(
        &self,
        tenant_id: &str,
        skill_id: &str,
    ) -> Result<Option<SkillManifest>, EngineError>;
    async fn read_skill_docs(&self, skill_id: &str) -> Result<Option<String>, EngineError>;
    async fn register_remote_skill(
        &self,
        p: RemoteSkillPublication,
    ) -> Result<SkillManifest, EngineError>;
    async fn revoke_skill(&self, provider_did: &str, skill_id: &str) -> Result<(), EngineError>;
}

#[async_trait]
pub trait EconomicSettlementEngine: Send + Sync {
    async fn reserve_budget(
        &self,
        tenant_id: &str,
        payer_did: &str,
        skill: &SkillManifest,
    ) -> Result<Option<EconomicClaim>, EngineError>;
    async fn settle_reservation(
        &self,
        reservation_id: &str,
        outcome: &Result<ExecutionResult, EngineError>,
    ) -> Result<Option<ExecutionReceipt>, EngineError>;
}

#[async_trait]
pub trait ReputationEvaluator: Send + Sync {
    async fn evaluate_counterparty(
        &self,
        tenant_id: &str,
        caller_did: &str,
        skill: &SkillManifest,
        receipts: &[ExecutionReceipt],
    ) -> Result<ReputationDecision, EngineError>;
    async fn record_outcome(
        &self,
        tenant_id: &str,
        caller_did: &str,
        provider_did: &str,
        success: bool,
    ) -> Result<(), EngineError>;
}

#[async_trait]
pub trait ExecutorDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        m: &SkillManifest,
        a: &TrustEnvelope<ProposedAction>,
        grant_jwt: &str,
    ) -> Result<ExecutionResult, EngineError>;
}

#[async_trait]
pub trait TaintAndLineageEngine: Send + Sync {
    async fn record_tool_output(
        &self,
        tenant_id: &str,
        trace_id: &str,
        skill: &SkillManifest,
        output: &serde_json::Value,
    ) -> Result<(), EngineError>;
    async fn evaluate_taint_and_lineage(
        &self,
        tenant_id: &str,
        trace_id: &str,
        target: &SkillManifest,
        canonical_args: &serde_json::Value,
    ) -> Result<TaintDecision, EngineError>;
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn append(&self, ev: AuditEvent) -> Result<(), EngineError>;
}

#[async_trait]
pub trait TenantResolver: Send + Sync {
    async fn resolve_tenant(&self, tenant_id: &str) -> Result<(), EngineError>;
}

impl From<trust_sdk::grants::GrantError> for EngineError {
    fn from(err: trust_sdk::grants::GrantError) -> Self {
        EngineError::Internal(err.to_string())
    }
}
