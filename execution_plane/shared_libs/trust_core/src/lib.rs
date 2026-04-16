// ─────────────────────────────────────────────────────────────
// trust_core — Canonical domain types for the Sovereign Trust
// & Approval Gateway.
//
// This crate contains ONLY pure domain types and trait definitions.
// It has zero transport dependencies (no Axum, no NATS, no JWT lib).
// Every other gateway crate depends on trust_core.
// ─────────────────────────────────────────────────────────────

pub mod action;
pub mod actor;
pub mod agent;
pub mod approval;
pub mod audit;
pub mod decision;
pub mod errors;
pub mod grant;
pub mod normalizer;
pub mod proof;
pub mod skill;
pub mod traits;

// Re-export the most commonly used types at crate root for ergonomics.
pub use action::{ActionDescriptor, ActionRequest, ActionResult, ActionStatus, OperationKind};
pub use actor::{ActorContext, AuthLevel, SourceContext};
pub use approval::{ApprovalRecord, ApprovalRequest, ApprovalResult, ApprovalStatus, ApprovalTier};
pub use audit::{AuditEvent, AuditEventType};
pub use decision::ActionDecision;
pub use errors::*;
pub use grant::{ExecutionGrant, GrantClearance, SignedGrant};
pub use normalizer::{
    ActionReview, BusinessDiffField, NormalizedAction, PolicyEvaluationDisplay, RiskLevel,
};
pub use proof::{ProofCallback, ProofChallenge, ProofRequest, ProofResult, ProofType};
pub use skill::{ExecutorType, SkillAction, SkillManifest};
pub use agent::{AgentRecord, AgentType, AgentEnvironment, AgentStatus, RegisterAgentRequest, UpdateAgentRequest};
pub use traits::{
    AgentRegistry, ApprovalStore, AuditSink, ConnectorDispatcher, GrantIssuer, PolicyEngine,
    ProofVerifier,
};

/// Monetary value with currency code (ISO 4217).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Money {
    /// Amount in the smallest currency unit (e.g., cents for EUR).
    pub amount_minor: i64,
    /// ISO 4217 currency code, e.g. "EUR", "USD".
    pub currency: String,
}

impl Money {
    pub fn new(amount_minor: i64, currency: impl Into<String>) -> Self {
        Self {
            amount_minor,
            currency: currency.into(),
        }
    }

    /// Convenience: create from a major-unit float (e.g. 100.50 EUR).
    /// Rounds to nearest minor unit.
    pub fn from_major(amount: f64, currency: impl Into<String>) -> Self {
        Self {
            amount_minor: (amount * 100.0).round() as i64,
            currency: currency.into(),
        }
    }

    /// Return the major-unit value (e.g. 1.50 for 150 cents).
    pub fn as_major(&self) -> f64 {
        self.amount_minor as f64 / 100.0
    }
}

impl std::fmt::Display for Money {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.2} {}", self.as_major(), self.currency)
    }
}
