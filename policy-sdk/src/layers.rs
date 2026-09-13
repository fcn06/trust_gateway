use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Deny { reason: String },
    RequiresHumanApproval { clearance_required: String },
}

/// 1. Platform Policy — Non-bypassable platform invariants.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformPolicy {
    pub enforce_signature: bool,
    pub enforce_tenant_isolation: bool,
    pub enforce_replay_prevention: bool,
    pub max_grant_ttl_seconds: u64,
}

/// 2. Organization Policy — Enterprise rules & caps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrganizationPolicy {
    pub allowed_regions: Vec<String>,
    pub max_financial_limit_usd: u64,
    pub blacklisted_tools: Vec<String>,
    #[serde(default)]
    pub min_reputation_successful_executions: Option<u64>,
    #[serde(default)]
    pub trusted_peer_roots: Vec<String>,
}

/// 3. Agent Policy — Capabilities assigned to an agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentPolicy {
    pub agent_id: String,
    pub allowed_tools: Vec<String>,
    pub max_delegation_depth: u8,
}

/// 4. Transaction Policy — Contextual transaction rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionPolicy {
    pub tool_name: String,
    pub human_approval_threshold_usd: Option<u64>,
    pub required_executor_profile: Option<String>,
}

/// Combined 4-Layer Hierarchical Policy Definition
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HierarchicalPolicy {
    pub platform: PlatformPolicy,
    pub organization: OrganizationPolicy,
    pub agent: AgentPolicy,
    pub transaction: TransactionPolicy,
}
