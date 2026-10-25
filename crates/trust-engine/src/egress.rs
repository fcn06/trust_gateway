use crate::traits::EngineError;
use regex::Regex;
use std::sync::LazyLock;
use trust_sdk::manifest::EgressClassification;

static PII_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // Email
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
        // API Keys (e.g. OpenAI / Stripe)
        Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap(),
        Regex::new(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b").unwrap(),
        // JWT tokens
        Regex::new(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b").unwrap(),
        // Credit card
        Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b").unwrap(),
    ]
});

pub struct EgressProcessor;

impl EgressProcessor {
    pub fn scrub_text(text: &str) -> String {
        let mut result = text.to_string();
        for pattern in PII_PATTERNS.iter() {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }
        result
    }

    pub fn scrub_value(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                *s = Self::scrub_text(s);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    Self::scrub_value(item);
                }
            }
            serde_json::Value::Object(map) => {
                for (_k, v) in map.iter_mut() {
                    Self::scrub_value(v);
                }
            }
            _ => {}
        }
    }

    /// Validates egress payload size and allowed fields, and scrubs PII.
    /// CRITICAL: Reject oversize payloads, NEVER truncate!
    pub fn process_egress(
        output: &serde_json::Value,
        egress_spec: &EgressClassification,
    ) -> Result<serde_json::Value, EngineError> {
        let json_str = serde_json::to_string(output)
            .map_err(|e| EngineError::Internal(format!("Failed to serialize output: {e}")))?;

        let byte_len = json_str.len();
        if byte_len > egress_spec.max_payload_bytes && egress_spec.max_payload_bytes > 0 {
            return Err(EngineError::EgressPayloadTooLarge {
                size: byte_len,
                max: egress_spec.max_payload_bytes,
            });
        }

        let mut processed = output.clone();
        Self::scrub_value(&mut processed);

        // Filter allowed fields if specified
        if !egress_spec.allowed_fields.is_empty() {
            if let serde_json::Value::Object(ref mut map) = processed {
                map.retain(|k, _| egress_spec.allowed_fields.contains(k));
            }
        }

        Ok(processed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_scrubbing() {
        let text = "Contact alice@example.com with secret sk-1234567890abcdef1234567890!";
        let scrubbed = EgressProcessor::scrub_text(text);
        assert!(!scrubbed.contains("alice@example.com"));
        assert!(!scrubbed.contains("sk-1234567890abcdef1234567890"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn test_oversize_payload_strictly_rejected() {
        let large_string = "a".repeat(1000);
        let val = serde_json::json!({ "data": large_string });
        let spec = EgressClassification {
            contains_pii: false,
            max_payload_bytes: 100, // strict 100 byte limit
            allowed_fields: vec![],
        };

        let result = EgressProcessor::process_egress(&val, &spec);
        assert!(matches!(
            result,
            Err(EngineError::EgressPayloadTooLarge { size, max }) if size > 100 && max == 100
        ));
    }
}
