// ─────────────────────────────────────────────────────────────
// trust_policy — Attribute-based policy engine
//
// Replaces the blunt `safe_tools` array in policy.json with
// rich, attribute-based rule matching. Rules are loaded from
// a `policy.toml` file and evaluated against ActionRequests.
// ─────────────────────────────────────────────────────────────

pub mod config;
pub mod engine;
pub mod matcher;
pub mod rules;

pub use config::PolicyConfig;
pub use engine::TomlPolicyEngine;
pub use rules::{PolicyEffect, PolicyRule, PolicySet};
