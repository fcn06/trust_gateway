// ─────────────────────────────────────────────────────────────
// Agent Registry — domain types
//
// Every agent, swarm, or automation that interacts with the
// Trust Gateway must be registered with a distinct identity.
//
// This module holds pure domain types with zero transport deps,
// following the same pattern as action.rs, approval.rs, etc.
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// A registered agent in the governance system.
///
/// This is the minimal record needed for:
/// - Identifiable audit trails
/// - Policy-bound execution
/// - Manual revocation (kill switch)
/// - Visibility in the portal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Unique identifier for this agent (UUID v4 or config-defined).
    pub agent_id: String,

    /// Human-readable name, e.g. "SSI Agent", "Order Swarm Alpha".
    pub name: String,

    /// Owner DID or user ID — who is responsible for this agent.
    pub owner: String,

    /// Classification of this agent.
    pub agent_type: AgentType,

    /// Deployment environment.
    pub environment: AgentEnvironment,

    /// Policy profile name that maps to policy.toml rules.
    /// e.g. "internal_default", "external_restricted", "automation_readonly"
    pub policy_profile: String,

    /// Specific tool names this agent is allowed to invoke.
    /// Empty means "governed by policy_profile only" (no tool-level allowlist).
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// The identity source this agent delegates from.
    /// e.g. a DID, an SSO principal, or "system" for internal agents.
    pub delegated_identity: String,

    /// Current lifecycle status.
    pub status: AgentStatus,

    /// Emergency kill switch — overrides status.
    /// When true, the agent is immediately blocked from all execution
    /// regardless of policy evaluation.
    #[serde(default)]
    pub kill_switch: bool,

    /// When this agent was first registered.
    pub created_at: DateTime<Utc>,

    /// Last time this agent was seen proposing an action.
    pub last_seen: Option<DateTime<Utc>>,

    /// Optional metadata for extensibility.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Classification of agent types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    /// Internal orchestrator (e.g. ssi_agent).
    InternalAgent,
    /// External AI swarm connecting via API.
    ExternalSwarm,
    /// Automated workflow or cron-triggered process.
    Automation,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalAgent => write!(f, "internal_agent"),
            Self::ExternalSwarm => write!(f, "external_swarm"),
            Self::Automation => write!(f, "automation"),
        }
    }
}

/// Deployment environment for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEnvironment {
    Dev,
    Staging,
    Prod,
}

impl std::fmt::Display for AgentEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dev => write!(f, "dev"),
            Self::Staging => write!(f, "staging"),
            Self::Prod => write!(f, "prod"),
        }
    }
}

/// Lifecycle status of a registered agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Agent is active and allowed to propose actions.
    Active,
    /// Agent is temporarily paused (not denied — just suspended).
    Paused,
    /// Agent's registration has been permanently revoked.
    Revoked,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// Request payload for registering a new agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAgentRequest {
    pub name: String,
    pub owner: String,
    pub agent_type: AgentType,
    pub environment: AgentEnvironment,
    pub policy_profile: String,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    pub delegated_identity: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Request payload for updating an existing agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAgentRequest {
    pub name: Option<String>,
    pub owner: Option<String>,
    pub environment: Option<AgentEnvironment>,
    pub policy_profile: Option<String>,
    pub allowed_tools: Option<Vec<String>>,
    pub delegated_identity: Option<String>,
    pub status: Option<AgentStatus>,
    pub kill_switch: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}

/// TOML-friendly representation for bootstrap configuration.
///
/// Used by `config/agents.toml` to pre-register agents at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootstrapEntry {
    pub agent_id: String,
    pub name: String,
    pub owner: String,
    pub agent_type: AgentType,
    pub environment: AgentEnvironment,
    pub policy_profile: String,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    pub delegated_identity: String,
}

/// Top-level structure for agents.toml parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootstrapConfig {
    #[serde(default)]
    pub agents: Vec<AgentBootstrapEntry>,
}
