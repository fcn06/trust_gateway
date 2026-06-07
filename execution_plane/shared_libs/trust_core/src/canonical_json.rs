// ─────────────────────────────────────────────────────────────
// Canonical JSON — deterministic serialization
//
// Produces a byte-stable JSON representation suitable for
// cryptographic hashing. Keys are sorted lexicographically at
// all nesting levels and no extraneous whitespace is emitted.
//
// This is used to compute `input_hash` for ExecutionGrants,
// ensuring the same logical arguments always produce the same
// SHA-256 hash regardless of insertion order.
// ─────────────────────────────────────────────────────────────

use sha2::{Digest, Sha256};

/// Serialize a JSON value into canonical form (sorted keys, no whitespace).
///
/// This is NOT the same as `serde_json::to_string()` which preserves
/// insertion order. Canonical JSON guarantees byte-stable output.
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_str =
                        serde_json::to_string(*k).unwrap_or_else(|_| format!("\"{}\"", k));
                    let val_str = canonical_json(obj.get(*k).unwrap());
                    format!("{}:{}", key_str, val_str)
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// Compute the SHA-256 hash of canonical JSON for a given value.
///
/// Returns the hex-encoded hash string. Used for `ExecutionGrant.input_hash`.
pub fn canonical_hash(value: &serde_json::Value) -> String {
    let canonical = canonical_json(value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_json_sorted_keys() {
        let json = serde_json::json!({
            "zebra": 1,
            "alpha": 2,
            "middle": 3,
        });
        let result = canonical_json(&json);
        assert_eq!(result, r#"{"alpha":2,"middle":3,"zebra":1}"#);
    }

    #[test]
    fn test_canonical_json_nested_sorted() {
        let json = serde_json::json!({
            "b": {"z": 1, "a": 2},
            "a": 3,
        });
        let result = canonical_json(&json);
        assert_eq!(result, r#"{"a":3,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_canonical_json_no_whitespace() {
        let json = serde_json::json!({"key": "value", "num": 42});
        let result = canonical_json(&json);
        assert!(
            !result.contains(' '),
            "Canonical JSON must have no whitespace"
        );
    }

    #[test]
    fn test_canonical_json_arrays_preserved() {
        let json = serde_json::json!({"items": [3, 1, 2]});
        let result = canonical_json(&json);
        // Array order is preserved (not sorted — only object keys are sorted)
        assert_eq!(result, r#"{"items":[3,1,2]}"#);
    }

    #[test]
    fn test_canonical_json_deterministic() {
        // Same logical object, different insertion order
        let a = serde_json::json!({"x": 1, "y": 2, "z": 3});
        let b = serde_json::json!({"z": 3, "x": 1, "y": 2});
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn test_canonical_hash_deterministic() {
        let a = serde_json::json!({"action": "create", "resource": "event"});
        let b = serde_json::json!({"resource": "event", "action": "create"});
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn test_canonical_hash_different_values() {
        let a = serde_json::json!({"action": "create"});
        let b = serde_json::json!({"action": "delete"});
        assert_ne!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn test_canonical_json_strings_escaped() {
        let json = serde_json::json!({"msg": "hello \"world\""});
        let result = canonical_json(&json);
        assert!(result.contains(r#"\"world\""#));
    }

    #[test]
    fn test_canonical_json_null_bool() {
        let json = serde_json::json!({"a": null, "b": true, "c": false});
        let result = canonical_json(&json);
        assert_eq!(result, r#"{"a":null,"b":true,"c":false}"#);
    }
}
