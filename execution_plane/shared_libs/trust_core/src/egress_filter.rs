// ─────────────────────────────────────────────────────────────
// Egress Filter — redacts sensitive data from executor output
//
// WS-H3: Implements regex-based redaction patterns for PII and
// secrets that should never be exposed to the LLM or audit trail.
//
// Applied as a post-processing step on native_skill_executor output
// before the response is returned to the Trust Gateway.
//
// RULE: Redaction patterns are conservative — they replace the
// full match with a placeholder to prevent partial leaks.
// ─────────────────────────────────────────────────────────────

use regex::Regex;
use std::sync::LazyLock;

/// A single redaction rule with a compiled regex and a replacement string.
struct RedactionRule {
    name: &'static str,
    pattern: Regex,
    replacement: &'static str,
}

/// Pre-compiled redaction rules. Initialized once, used for every request.
static REDACTION_RULES: LazyLock<Vec<RedactionRule>> = LazyLock::new(|| {
    vec![
        // ── Credit Card Numbers ─────────────────────────────────
        // Matches Visa, MasterCard, Amex, Discover patterns
        // (13-19 digits with optional separators)
        RedactionRule {
            name: "credit_card",
            pattern: Regex::new(
                r"\b(?:\d[ -]*?){13,19}\b"
            ).expect("credit_card regex"),
            replacement: "[REDACTED:credit_card]",
        },
        // More precise: Luhn-plausible card number patterns
        RedactionRule {
            name: "credit_card_formatted",
            pattern: Regex::new(
                r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,7}\b"
            ).expect("credit_card_formatted regex"),
            replacement: "[REDACTED:credit_card]",
        },

        // ── API Keys / Secrets ──────────────────────────────────
        // Stripe keys (sk_live_*, pk_live_*, sk_test_*, rk_live_*)
        RedactionRule {
            name: "stripe_key",
            pattern: Regex::new(
                r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"
            ).expect("stripe_key regex"),
            replacement: "[REDACTED:stripe_key]",
        },
        // OpenAI API keys (sk-...)
        RedactionRule {
            name: "openai_key",
            pattern: Regex::new(
                r"\bsk-[A-Za-z0-9_-]{20,}\b"
            ).expect("openai_key regex"),
            replacement: "[REDACTED:openai_key]",
        },
        // AWS Access Keys (AKIA...)
        RedactionRule {
            name: "aws_access_key",
            pattern: Regex::new(
                r"\bAKIA[0-9A-Z]{16}\b"
            ).expect("aws_access_key regex"),
            replacement: "[REDACTED:aws_access_key]",
        },
        RedactionRule {
            name: "aws_secret_key",
            pattern: Regex::new(
                r#"(?i)(?:aws_secret_access_key|secret_key|secretaccesskey)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#
            ).expect("aws_secret_key regex"),
            replacement: "[REDACTED:aws_secret_key]",
        },
        // Generic Bearer tokens in strings
        RedactionRule {
            name: "bearer_token",
            pattern: Regex::new(
                r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"
            ).expect("bearer_token regex"),
            replacement: "[REDACTED:bearer_token]",
        },

        // ── Email Addresses ─────────────────────────────────────
        RedactionRule {
            name: "email",
            pattern: Regex::new(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ).expect("email regex"),
            replacement: "[REDACTED:email]",
        },

        // ── Phone Numbers ───────────────────────────────────────
        // International format: +1-234-567-8901 or +44 7911 123456
        RedactionRule {
            name: "phone_international",
            pattern: Regex::new(
                r"\+[1-9]\d{0,2}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}"
            ).expect("phone_international regex"),
            replacement: "[REDACTED:phone]",
        },

        // ── Social Security Numbers (US) ────────────────────────
        RedactionRule {
            name: "ssn",
            pattern: Regex::new(
                r"\b\d{3}-\d{2}-\d{4}\b"
            ).expect("ssn regex"),
            replacement: "[REDACTED:ssn]",
        },

        // ── Private Keys (PEM format) ───────────────────────────
        RedactionRule {
            name: "private_key_pem",
            pattern: Regex::new(
                r"-----BEGIN (?:RSA |EC |ED25519 )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ED25519 )?PRIVATE KEY-----"
            ).expect("private_key_pem regex"),
            replacement: "[REDACTED:private_key]",
        },

        // ── JWT Tokens (3-segment base64) ───────────────────────
        RedactionRule {
            name: "jwt_token",
            pattern: Regex::new(
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
            ).expect("jwt_token regex"),
            replacement: "[REDACTED:jwt]",
        },
        // ── IBAN Numbers ────────────────────────────────────────
        RedactionRule {
            name: "iban",
            pattern: Regex::new(
                r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){4,30}\b"
            ).expect("iban regex"),
            replacement: "[REDACTED:iban]",
        },
    ]
});

/// Apply all redaction rules to a string, returning the scrubbed output.
///
/// This is the primary entry point for the egress filter.
pub fn redact(input: &str) -> String {
    let mut output = input.to_string();
    for rule in REDACTION_RULES.iter() {
        if rule.pattern.is_match(&output) {
            let before_len = output.len();
            output = rule
                .pattern
                .replace_all(&output, rule.replacement)
                .to_string();
            if output.len() != before_len {
                tracing::debug!(
                    "🔒 Egress filter: redacted {} pattern(s) for '{}'",
                    rule.name,
                    rule.name
                );
            }
        }
    }
    output
}

/// Apply egress filtering to a JSON value, recursively scrubbing string fields.
///
/// This walks the entire JSON tree and applies redaction patterns to all
/// string values. Object keys are NOT scrubbed (they are schema-defined).
pub fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            let scrubbed = redact(s);
            if scrubbed != *s {
                *s = scrubbed;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json(item);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_key, val) in obj.iter_mut() {
                redact_json(val);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_credit_card() {
        let input = "Card number: 4111-1111-1111-1111 was charged.";
        let output = redact(input);
        assert!(!output.contains("4111"), "Credit card should be redacted");
        assert!(output.contains("[REDACTED:credit_card]"));
    }

    #[test]
    fn redacts_stripe_key() {
        let input = "Using key sk_live_abcdefghijklmnopqrstuvwxyz for payment";
        let output = redact(input);
        assert!(
            !output.contains("sk_live_"),
            "Stripe key should be redacted"
        );
        assert!(output.contains("[REDACTED:stripe_key]"));
    }

    #[test]
    fn redacts_openai_key() {
        let input = "API key: sk-proj_abcdefghijklmnopqrstuvwxyz123456";
        let output = redact(input);
        assert!(
            !output.contains("sk-proj_"),
            "OpenAI key should be redacted"
        );
    }

    #[test]
    fn redacts_aws_access_key() {
        let input = "AWS key: AKIAIOSFODNN7EXAMPLE";
        let output = redact(input);
        assert!(!output.contains("AKIA"), "AWS key should be redacted");
        assert!(output.contains("[REDACTED:aws_access_key]"));
    }

    #[test]
    fn redacts_email() {
        let input = "Contact user@example.com for details";
        let output = redact(input);
        assert!(
            !output.contains("user@example.com"),
            "Email should be redacted"
        );
        assert!(output.contains("[REDACTED:email]"));
    }

    #[test]
    fn redacts_ssn() {
        let input = "SSN: 123-45-6789";
        let output = redact(input);
        assert!(!output.contains("123-45-6789"), "SSN should be redacted");
        assert!(output.contains("[REDACTED:ssn]"));
    }

    #[test]
    fn redacts_phone() {
        let input = "Call +1-555-123-4567 for support";
        let output = redact(input);
        assert!(!output.contains("+1-555"), "Phone should be redacted");
        assert!(output.contains("[REDACTED:phone]"));
    }

    #[test]
    fn redacts_jwt() {
        let input = "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let output = redact(input);
        assert!(!output.contains("eyJhbG"), "JWT should be redacted");
        assert!(output.contains("[REDACTED:jwt]"));
    }

    #[test]
    fn redacts_iban() {
        let input = "My IBAN is DE89370400440532013000.";
        let output = redact(input);
        assert!(!output.contains("DE89"), "IBAN should be redacted");
        assert!(output.contains("[REDACTED:iban]"));
    }

    #[test]
    fn preserves_clean_text() {
        let input = "The weather in Paris is 22°C and sunny.";
        let output = redact(input);
        assert_eq!(input, output, "Clean text should not be modified");
    }

    #[test]
    fn redacts_json_values() {
        let mut value = serde_json::json!({
            "name": "Test User",
            "email": "test@example.com",
            "data": {
                "card": "4111-1111-1111-1111"
            },
            "count": 42
        });
        redact_json(&mut value);

        let email = value["email"].as_str().unwrap();
        assert!(email.contains("[REDACTED:email]"));

        let card = value["data"]["card"].as_str().unwrap();
        assert!(card.contains("[REDACTED:credit_card]"));

        // Non-string values preserved
        assert_eq!(value["count"], 42);
        assert_eq!(value["name"], "Test User");
    }
}
