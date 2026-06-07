// ─────────────────────────────────────────────────────────────
// Action lifecycle types
// ─────────────────────────────────────────────────────────────

use crate::actor::{ActorContext, SourceContext};
use crate::Money;
use serde::{Deserialize, Serialize};

/// The canonical action request that flows through the entire gateway.
///
/// Created when any proposer (ssi_agent, webhook, WhatsApp bridge, PicoClaw)
/// submits an action for governance.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NormalizedActionProposal {
    pub tenant_id: String,
    pub requester_id: String,
    pub source_type: String, // host | a2a | mcp | webhook
    pub auth_method: String,
    pub auth_level: String,
    pub scopes: Vec<String>,
    pub tool_server: String,
    pub tool_name: String,
    pub action_name: String,
    pub action_arguments: serde_json::Value,
    pub payload: serde_json::Value,
    pub transport_metadata: Option<serde_json::Value>,
    pub planning_context: Option<serde_json::Value>,
}
///
/// Created when any proposer (ssi_agent, webhook, WhatsApp bridge, PicoClaw)
/// submits an action for governance.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActionRequest {
    /// Unique identifier for this action attempt.
    pub action_id: String,
    /// Tenant that owns the resources being acted upon.
    pub tenant_id: String,
    /// Identity context: who is asking and under what authority.
    pub actor: ActorContext,
    /// Where the action originated (ssi_agent, whatsapp, webhook, etc.).
    pub source: SourceContext,
    /// What is being requested — the action descriptor.
    pub action: ActionDescriptor,
}

/// Describes a concrete action that an agent or automation wants to execute.
///
/// This replaces the old raw tool-name dispatch. Every action is now
/// classified by name, category, operation kind, optional monetary amount,
/// and risk-tagging hints.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActionDescriptor {
    /// Fully qualified action name, e.g. "google.calendar.event.create".
    pub name: String,
    /// Business category, e.g. "scheduling", "refund", "payment".
    pub category: String,
    /// Optional resource identifier (e.g. order ID, calendar ID).
    pub resource: Option<String>,
    /// Kind of operation being performed.
    pub operation: OperationKind,
    /// Monetary value involved, if any (used for threshold-based policy).
    pub amount: Option<Money>,
    /// Raw arguments to pass to the executor.
    pub arguments: serde_json::Value,
    /// Free-form risk/classification tags, e.g. ["mutation", "external_api",
    /// "payout_change"]. Policy rules can match on these.
    pub tags: Vec<String>,
}

/// The kind of operation an action performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Read,
    Create,
    Update,
    Delete,
    Transfer,
}

impl std::fmt::Display for OperationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::Transfer => write!(f, "transfer"),
        }
    }
}

/// The terminal status of an executed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Succeeded,
    Failed,
}

/// Result returned after a connector executes an action.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActionResult {
    /// Correlates back to the original `ActionRequest.action_id`.
    pub action_id: String,
    /// Terminal status.
    pub status: ActionStatus,
    /// Which connector handled the action.
    pub connector: String,
    /// Optional external reference from the SaaS system
    /// (e.g. Shopify refund ID, Google event ID).
    pub external_reference: Option<String>,
    /// Structured output from the connector.
    pub output: serde_json::Value,
}

/// Infer operation kind from action name conventions.
pub fn infer_operation(name: &str) -> OperationKind {
    let lower = name.to_lowercase();
    if lower.contains("list")
        || lower.contains("get")
        || lower.contains("read")
        || lower.contains("search")
        || lower.contains("fetch")
    {
        OperationKind::Read
    } else if lower.contains("create")
        || lower.contains("add")
        || lower.contains("new")
        || lower.contains("insert")
    {
        OperationKind::Create
    } else if lower.contains("update")
        || lower.contains("edit")
        || lower.contains("modify")
        || lower.contains("set")
    {
        OperationKind::Update
    } else if lower.contains("delete") || lower.contains("remove") || lower.contains("cancel") {
        OperationKind::Delete
    } else if lower.contains("refund")
        || lower.contains("transfer")
        || lower.contains("send")
        || lower.contains("pay")
    {
        OperationKind::Transfer
    } else {
        OperationKind::Create
    }
}

/// Infer category from action name prefix.
pub fn infer_category(name: &str) -> String {
    // Try dot notation first: "google.calendar.event.create" → "google"
    if let Some(first) = name.split('.').next() {
        if first != name {
            return first.to_string();
        }
    }
    // Try underscore: "google_calendar_list_events" → "google"
    name.split('_').next().unwrap_or("unknown").to_string()
}

