use sha2::{Digest, Sha256};

/// Recursively produces canonical JSON string with sorted object keys (RFC 8785).
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let pairs: Vec<String> = entries
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Compute SHA-256 hex digest of canonical JSON.
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
    fn test_canonical_json_sorting() {
        let json1 = serde_json::json!({"b": 2, "a": 1});
        let json2 = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(canonical_json(&json1), canonical_json(&json2));
        assert_eq!(canonical_hash(&json1), canonical_hash(&json2));
    }

    #[test]
    fn test_rfc8785_key_order_invariance() {
        let json1 = serde_json::json!({
            "z": "last",
            "a": 123,
            "m": { "k2": true, "k1": "nested" }
        });
        let json2 = serde_json::json!({
            "a": 123,
            "m": { "k1": "nested", "k2": true },
            "z": "last"
        });
        assert_eq!(canonical_json(&json1), canonical_json(&json2));
        assert_eq!(canonical_hash(&json1), canonical_hash(&json2));
    }

    #[test]
    fn test_input_hash_stability() {
        let args = serde_json::json!({
            "title": "Team Sync",
            "duration": 30
        });
        let hash = canonical_hash(&args);
        assert_eq!(
            hash,
            "a548773f525c1e330e21c20ecebf3fb7a5fdf48cca55fda1a78d177756e4b70e"
        );

        // Key order invariance test
        let args_reversed = serde_json::json!({
            "duration": 30,
            "title": "Team Sync"
        });
        assert_eq!(canonical_hash(&args_reversed), hash);
    }

    #[test]
    fn test_load_test_vectors() {
        let vector_path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/valid_grant.json");
        if let Ok(content) = std::fs::read_to_string(vector_path) {
            let val: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(val["grant_id"], "grant_val_001");
            assert_eq!(val["allowed_action"], "google.calendar.event.create");
            assert!(val["input_hash"].as_str().is_some());
        }
    }
}
