// ─────────────────────────────────────────────────────────────
// trust_policy — Attribute-based policy engine
//
// Replaces the blunt `safe_tools` array in policy.json with
// rich, attribute-based rule matching. Rules are loaded from
// a `policy.toml` file and evaluated against ActionRequests.
// ─────────────────────────────────────────────────────────────

pub mod engine;
pub mod rules;
pub mod matcher;
pub mod config;

pub use engine::TomlPolicyEngine;
pub use rules::{PolicyRule, PolicySet, PolicyEffect};
pub use config::PolicyConfig;
