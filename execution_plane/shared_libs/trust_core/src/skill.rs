// ─────────────────────────────────────────────────────────────
// Skill manifest types (Claw Logic + MCP)
//
// Models both hardcoded MCP tools and dynamic file-system
// discovered CLI skills in a unified registry.
// ─────────────────────────────────────────────────────────────

use crate::action::OperationKind;
use serde::{Deserialize, Serialize};

/// Executor backend type — determines how the Trust Gateway
/// routes an action after issuing an ExecutionGrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorType {
    /// Hardcoded MCP connector (connector_mcp_server).
    /// Google Calendar, Shopify, Stripe, etc.
    Mcp,
    /// Dynamic CLI skill discovered from /skills/*/manifest.json.
    /// Executed by the Native Skill Executor.
    Claw,
    /// VP-secured local tools (vp_mcp_server).
    Vp,
}

impl std::fmt::Display for ExecutorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mcp => write!(f, "mcp"),
            Self::Claw => write!(f, "claw"),
            Self::Vp => write!(f, "vp"),
        }
    }
}

/// A skill manifest — describes one integration (MCP or Claw) and
/// the actions it exposes.
///
/// For MCP skills, this is synthesized from the hardcoded
/// `connector_mcp_server` tool registry.
///
/// For Claw skills, this is loaded from `/skills/{id}/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    /// Unique skill identifier, e.g. "google_calendar", "custom_crm_sync".
    pub id: String,
    /// Human-readable name, e.g. "Google Calendar".
    pub name: String,
    /// Description of what this skill does.
    pub description: String,
    /// How this skill is executed.
    pub executor_type: ExecutorType,
    /// Path to the executable script (Claw skills only).
    /// Relative to the skill directory.
    pub executable: Option<String>,
    /// Environment variable name to inject the OAuth token into
    /// (Claw skills only), e.g. "GOOGLE_ACCESS_TOKEN".
    pub env_token_key: Option<String>,
    /// OAuth provider identifier, if the skill requires OAuth.
    /// Used to look up tokens from the tenant token store.
    pub oauth_provider: Option<String>,
    /// The actions this skill exposes to the LLM.
    pub actions: Vec<SkillAction>,
}

/// A single action exposed by a skill.
///
/// The LLM sees these as callable tools. The `executor_type` is
/// NOT exposed to the LLM — it only sees name + description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillAction {
    /// Fully qualified action name, e.g. "google.calendar.event.create".
    /// This must be globally unique across all skills.
    pub name: String,
    /// Human-readable description for the LLM tool definition.
    pub description: Option<String>,
    /// Business category, e.g. "scheduling", "refund".
    pub category: String,
    /// Kind of operation (Read, Create, Update, Delete).
    pub operation: OperationKind,
    /// Risk/classification hints for the policy engine, e.g.
    /// `["mutation", "external_api", "payout_change"]`.
    pub risk_hints: Vec<String>,
    /// JSON Schema description of the action's input parameters.
    /// Used to generate LLM tool definitions.
    pub input_schema: Option<serde_json::Value>,
}

/// The unified skill registry — the response payload for
/// `GET /.well-known/skills.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRegistry {
    /// Version of the registry format.
    pub version: String,
    /// All registered skills (MCP + Claw + VP).
    pub skills: Vec<SkillManifest>,
}

impl SkillRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            skills: Vec::new(),
        }
    }

    /// Find a skill by its ID.
    pub fn find_skill(&self, skill_id: &str) -> Option<&SkillManifest> {
        self.skills.iter().find(|s| s.id == skill_id)
    }

    /// Find a skill action by its fully qualified name.
    /// Returns the (skill, action) pair.
    pub fn find_action(&self, action_name: &str) -> Option<(&SkillManifest, &SkillAction)> {
        for skill in &self.skills {
            if let Some(action) = skill.actions.iter().find(|a| a.name == action_name) {
                return Some((skill, action));
            }
        }
        None
    }

    /// Return a flat list of all action names across all skills.
    pub fn all_action_names(&self) -> Vec<&str> {
        self.skills
            .iter()
            .flat_map(|s| s.actions.iter().map(|a| a.name.as_str()))
            .collect()
    }
}

impl Default for SkillRegistry {
    fn default() -> Self {
        Self::new()
    }
}
