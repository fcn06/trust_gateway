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

/// Multi-dimensional dynamic trust telemetry provided by the Gateway or caller evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DynamicTrustMetrics {
    /// Number of historically verified successful executions.
    pub successful_executions: u64,
    /// Number of historically recorded failed executions (runtime errors, contract breaches).
    pub failed_executions: u64,
    /// Historical failure rate in range [0.0, 1.0].
    pub failure_rate: f64,
    /// Normalized peer attestation score in range [0.0, 1.0], derived from trusted peer root attestations.
    pub peer_attestation_score: Option<f64>,
    /// Transitive reputation score (PageRank-style centrality) if participating in federation.
    pub transitive_trust_score: Option<f64>,
}

/// Dynamic reputation policy rules configured in policy.toml under [organization.reputation].
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ReputationPolicy {
    /// Minimum successful executions required for cold-start exit (default: None).
    #[serde(default)]
    pub min_successful_executions: Option<u64>,
    /// Maximum allowable failure rate before automatic denial (e.g., 0.05 for 5%).
    #[serde(default)]
    pub max_failure_rate: Option<f64>,
    /// Minimum peer attestation score required to bypass human approval for high-risk tools.
    #[serde(default)]
    pub min_peer_score_for_auto_approval: Option<f64>,
    /// If true, borderline reputation downgrades decision to RequiresHumanApproval instead of Deny.
    #[serde(default = "default_adaptive_downgrade")]
    pub adaptive_downgrade: bool,
}

fn default_adaptive_downgrade() -> bool {
    true
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
    pub reputation: Option<ReputationPolicy>,
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
