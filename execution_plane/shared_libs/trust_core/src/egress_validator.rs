// ─────────────────────────────────────────────────────────────
// Egress Validator — Post-DLP deterministic gate
//
// Phase 2: Prevents raw JSON dumps, structural leaks, and validates
// that the output does not contain sensitive internal system identifiers.
// Applies after Semantic DLP (LLM) and before the response is sent.
// ─────────────────────────────────────────────────────────────

use crate::egress_filter::redact;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    pub max_response_bytes: usize,
    pub max_json_depth: usize,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: 65536, // 64KB max response size
            max_json_depth: 5,         // Max nesting before flagged as a raw dump
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressViolation {
    RawJsonDump,
    PiiDetected,
    InternalIdLeaked,
    ResponseTooLarge,
}

impl std::fmt::Display for EgressViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawJsonDump => write!(f, "Output resembles a raw system JSON dump"),
            Self::PiiDetected => write!(f, "Output contains unredacted PII or secrets"),
            Self::InternalIdLeaked => write!(f, "Output contains internal system identifiers"),
            Self::ResponseTooLarge => write!(f, "Output exceeds maximum allowed size"),
        }
    }
}

/// Validates the final string output intended for an external caller.
pub fn validate_egress(content: &str, config: &EgressConfig) -> Result<(), EgressViolation> {
    // 1. Size limit
    if content.len() > config.max_response_bytes {
        return Err(EgressViolation::ResponseTooLarge);
    }

    // 2. PII / Secrets check
    // We run the redaction engine. If it would change the text, it means
    // unredacted PII is present in the output.
    let scrubbed = redact(content);
    if scrubbed != content {
        return Err(EgressViolation::PiiDetected);
    }

    // 3. Internal ID Leaks
    if content.contains("did:twin:")
        || content.contains("did:web:")
        || content.contains("did:peer:")
        || content.contains("grant_id")
        || content.contains("NATS_NKEY")
        || has_nkey_seed_pattern(content)
    {
        return Err(EgressViolation::InternalIdLeaked);
    }

    // 4. Raw JSON Dump Detection
    // Try to parse it as JSON. If it parses and is deeper than allowed,
    // we consider it a raw data dump rather than a semantically processed response.
    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(content) {
        if json_depth(&json_val) > config.max_json_depth {
            return Err(EgressViolation::RawJsonDump);
        }
    }

    Ok(())
}

fn has_nkey_seed_pattern(content: &str) -> bool {
    static SEED_PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\bS[A-Z2-7]{57}\b").expect("seed pattern regex")
    });
    SEED_PATTERN.is_match(content)
}

fn json_depth(val: &serde_json::Value) -> usize {
    match val {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(obj) => 1 + obj.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_safe_summary() {
        let content = "The user has 3 upcoming meetings.";
        assert_eq!(validate_egress(content, &EgressConfig::default()), Ok(()));
    }

    #[test]
    fn test_blocks_raw_json_dump() {
        // Deeply nested JSON
        let content = r#"{
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": {
                                "level6": "data"
                            }
                        }
                    }
                }
            }
        }"#;
        assert_eq!(
            validate_egress(content, &EgressConfig::default()),
            Err(EgressViolation::RawJsonDump)
        );
    }

    #[test]
    fn test_blocks_pii() {
        let content = "The user's email is bob@example.com.";
        assert_eq!(
            validate_egress(content, &EgressConfig::default()),
            Err(EgressViolation::PiiDetected)
        );
    }

    #[test]
    fn test_blocks_internal_ids() {
        let content = "The agent did:twin:123 processed the request.";
        assert_eq!(
            validate_egress(content, &EgressConfig::default()),
            Err(EgressViolation::InternalIdLeaked)
        );
    }

    #[test]
    fn test_blocks_extended_dids_and_keys() {
        let content_web = "System URL: did:web:example.com";
        assert_eq!(
            validate_egress(content_web, &EgressConfig::default()),
            Err(EgressViolation::InternalIdLeaked)
        );

        let content_peer = "Target agent: did:peer:12345";
        assert_eq!(
            validate_egress(content_peer, &EgressConfig::default()),
            Err(EgressViolation::InternalIdLeaked)
        );

        let content_nkey = "Key setting: NATS_NKEY=UAAAAAAAA";
        assert_eq!(
            validate_egress(content_nkey, &EgressConfig::default()),
            Err(EgressViolation::InternalIdLeaked)
        );

        // 58-character NKey seed starting with S and matching base32 characters
        let seed = "SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let content_seed = format!("Leak seed: {}", seed);
        assert_eq!(
            validate_egress(&content_seed, &EgressConfig::default()),
            Err(EgressViolation::InternalIdLeaked)
        );
    }

    #[test]
    fn test_allows_action_id() {
        // action_id is common in structured responses and no longer blocked
        let content = "{\"action_id\": \"123\", \"result\": \"success\"}";
        assert_eq!(validate_egress(content, &EgressConfig::default()), Ok(()));
    }

    #[test]
    fn test_blocks_large_response() {
        let mut config = EgressConfig::default();
        config.max_response_bytes = 10;
        let content = "This is too long";
        assert_eq!(
            validate_egress(content, &config),
            Err(EgressViolation::ResponseTooLarge)
        );
    }
}
