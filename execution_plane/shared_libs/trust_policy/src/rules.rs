// ─────────────────────────────────────────────────────────────
// Policy rule types
//
// Defines the PolicySet, PolicyRule, and PolicyEffect structures
// that are loaded from policy.toml.
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use trust_core::approval::ApprovalTier;

use trust_core::proof::ProofType;

/// A complete set of policy rules loaded from a configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    /// Version of the policy format.
    #[serde(default = "default_version")]
    pub version: String,
    /// Ordered list of policy rules (evaluated by priority).
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

fn default_version() -> String {
    "1.0".to_string()
}

/// A single policy rule that matches against action attributes
/// and produces an effect (allow, deny, require approval, require proof).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule identifier, e.g. "read-actions-auto-allow".
    pub id: String,
    /// Priority: lower number = evaluated first. First match wins.
    pub priority: u32,
    /// Match conditions — all specified conditions must be true.
    #[serde(flatten)]
    pub matcher: PolicyMatcher,
    /// What happens when this rule matches.
    pub effect: String,
    /// Approval tier (for "require_approval" effect).
    pub tier: Option<String>,
    /// Proof type (for "require_proof" effect).
    pub proof_type: Option<String>,
    /// Required claims for proof (for "require_proof" effect).
    #[serde(default)]
    pub required_claims: Vec<String>,
    /// Human-readable reason for the decision.
    pub reason: Option<String>,
}

/// Conditions for matching an action against a policy rule.
///
/// All specified fields must match (AND logic). Fields that
/// are None or empty are ignored (wildcard).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMatcher {
    /// Match specific action names, e.g. ["google.calendar.event.create"].
    pub action_names: Option<Vec<String>>,
    /// Match business categories, e.g. ["scheduling", "refund"].
    pub categories: Option<Vec<String>>,
    /// Match operation kinds, e.g. ["read", "create"].
    pub operation_kinds: Option<Vec<String>>,
    /// Match specific tenant IDs.
    pub tenant_ids: Option<Vec<String>>,
    /// Match source types, e.g. ["ssi_agent", "webhook"].
    pub source_types: Option<Vec<String>>,
    /// Minimum monetary amount (e.g. "100.00 EUR").
    pub min_amount: Option<String>,
    /// Maximum monetary amount.
    pub max_amount: Option<String>,
    /// Match against action tags, e.g. ["payout_change", "identity_change"].
    pub tags: Option<Vec<String>>,
}

/// The resolved effect of a policy rule, with all parameters populated.
#[derive(Debug, Clone)]
pub enum PolicyEffect {
    Allow,
    Deny {
        reason: String,
    },
    RequireApproval {
        tier: ApprovalTier,
        reason: String,
    },
    RequireProof {
        proof_type: ProofType,
        required_claims: Vec<String>,
        reason: String,
    },
}

impl PolicyRule {
    /// Parse the string-based effect/tier/proof_type into a resolved PolicyEffect.
    pub fn resolve_effect(&self) -> PolicyEffect {
        let reason = self.reason.clone().unwrap_or_default();

        match self.effect.as_str() {
            "allow" => PolicyEffect::Allow,
            "deny" => PolicyEffect::Deny { reason },
            "require_approval" => {
                let tier = match self.tier.as_deref() {
                    Some("tier0") => ApprovalTier::Tier0AutoAllow,
                    Some("tier1") => ApprovalTier::Tier1PortalClick,
                    Some("tier2") => ApprovalTier::Tier2ReAuthenticate,
                    Some("tier3") => ApprovalTier::Tier3VerifiedPresentation,
                    _ => ApprovalTier::Tier1PortalClick, // Default to portal click
                };
                PolicyEffect::RequireApproval { tier, reason }
            }
            "require_proof" => {
                let proof_type = match self.proof_type.as_deref() {
                    Some("openid4vp") | None => ProofType::OpenId4Vp,
                    Some(_) => ProofType::OpenId4Vp, // Default to OID4VP for unknown types
                };
                PolicyEffect::RequireProof {
                    proof_type,
                    required_claims: self.required_claims.clone(),
                    reason,
                }
            }
            _ => PolicyEffect::Deny {
                reason: format!("Unknown policy effect: {}", self.effect),
            },
        }
    }
}

impl PolicySet {
    /// Load a PolicySet from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Load a PolicySet from a TOML file.
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let policy_set = Self::from_toml(&contents)?;
        Ok(policy_set)
    }

    /// Return rules sorted by priority (ascending — lowest number first).
    pub fn sorted_rules(&self) -> Vec<&PolicyRule> {
        let mut rules: Vec<&PolicyRule> = self.rules.iter().collect();
        rules.sort_by_key(|r| r.priority);
        rules
    }
}
