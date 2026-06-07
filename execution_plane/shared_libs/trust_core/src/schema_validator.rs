// ─────────────────────────────────────────────────────────────
// Schema Validator — runtime JSON Schema validation for ingress payloads
//
// WS-H2: Loads canonical JSON Schema snapshots from disk at startup
// and validates raw JSON payloads before deserialization. This prevents
// silent API drift and malformed data from entering the pipeline.
//
// The validator is designed to be initialized once and reused for all
// requests (schemas are compiled at startup for O(1) validation).
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::path::Path;

/// A compiled schema validator that can validate JSON payloads against
/// pre-loaded canonical schemas.
///
/// Initialize once at service startup, then call `validate()` on each
/// incoming payload.
pub struct SchemaValidator {
    /// Map of schema name → compiled JSON schema.
    schemas: HashMap<String, jsonschema::Validator>,
}

/// Errors from schema validation.
#[derive(Debug)]
pub struct ValidationError {
    pub schema_name: String,
    pub errors: Vec<String>,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Schema validation failed for '{}': [{}]",
            self.schema_name,
            self.errors.join("; ")
        )
    }
}

impl std::error::Error for ValidationError {}

impl SchemaValidator {
    /// Load all `.json` schema files from the given directory.
    ///
    /// Each file is expected to be a valid JSON Schema (draft-07).
    /// The schema name is derived from the filename (without extension).
    ///
    /// Returns an error if the directory is unreadable or any schema
    /// file cannot be parsed.
    pub fn from_directory(snapshot_dir: &Path) -> Result<Self, String> {
        let mut schemas = HashMap::new();

        let entries = std::fs::read_dir(snapshot_dir)
            .map_err(|e| format!("Cannot read snapshot directory {:?}: {}", snapshot_dir, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
            let path = entry.path();

            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            // Skip ".new.json" files (created by snapshot tests on mismatch)
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.ends_with(".new") {
                    continue;
                }
            }

            let schema_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| format!("Invalid filename: {:?}", path))?
                .to_string();

            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("Cannot read schema {:?}: {}", path, e))?;

            let schema_value: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| format!("Invalid JSON in schema {:?}: {}", path, e))?;

            let compiled = jsonschema::validator_for(&schema_value)
                .map_err(|e| format!("Cannot compile schema '{}': {}", schema_name, e))?;

            schemas.insert(schema_name, compiled);
        }

        Ok(Self { schemas })
    }

    /// Load a single schema from a JSON string (useful for testing).
    #[cfg(test)]
    pub fn from_json(name: &str, schema_json: &str) -> Result<Self, String> {
        let schema_value: serde_json::Value =
            serde_json::from_str(schema_json).map_err(|e| format!("Invalid JSON: {}", e))?;

        let compiled = jsonschema::validator_for(&schema_value)
            .map_err(|e| format!("Cannot compile schema: {}", e))?;

        let mut schemas = HashMap::new();
        schemas.insert(name.to_string(), compiled);
        Ok(Self { schemas })
    }

    /// List all loaded schema names (for diagnostics at startup).
    pub fn loaded_schemas(&self) -> Vec<&str> {
        self.schemas.keys().map(|s| s.as_str()).collect()
    }

    /// Validate a JSON value against a named schema.
    ///
    /// Returns `Ok(())` if the payload matches the schema, or
    /// `Err(ValidationError)` with all validation errors.
    ///
    /// If no schema is loaded for the given name, validation is skipped
    /// (returns `Ok(())`). This makes it safe to add new schemas
    /// incrementally without breaking existing code paths.
    pub fn validate(
        &self,
        schema_name: &str,
        payload: &serde_json::Value,
    ) -> Result<(), ValidationError> {
        let compiled = match self.schemas.get(schema_name) {
            Some(c) => c,
            None => {
                // No schema loaded for this name — skip validation
                return Ok(());
            }
        };

        let result = compiled.validate(payload);
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                let error_string = format!("{} at {}", e, e.instance_path);
                Err(ValidationError {
                    schema_name: schema_name.to_string(),
                    errors: vec![error_string],
                })
            }
        }
    }

    /// Validate a raw JSON byte slice against a named schema.
    ///
    /// Parses the bytes as JSON first, then validates.
    /// Returns `Err` if the bytes are not valid JSON or fail validation.
    pub fn validate_bytes(
        &self,
        schema_name: &str,
        raw: &[u8],
    ) -> Result<serde_json::Value, String> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| format!("Invalid JSON: {}", e))?;

        self.validate(schema_name, &value)
            .map_err(|e| e.to_string())?;

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_payload_passes() {
        let schema = r#"{
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        }"#;

        let validator = SchemaValidator::from_json("test", schema).unwrap();
        let payload = serde_json::json!({"name": "hello"});
        assert!(validator.validate("test", &payload).is_ok());
    }

    #[test]
    fn invalid_payload_fails() {
        let schema = r#"{
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        }"#;

        let validator = SchemaValidator::from_json("test", schema).unwrap();
        let payload = serde_json::json!({"name": 42});
        let err = validator.validate("test", &payload).unwrap_err();
        assert!(!err.errors.is_empty());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn missing_required_field_fails() {
        let schema = r#"{
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["action_id", "tenant_id"],
            "properties": {
                "action_id": { "type": "string" },
                "tenant_id": { "type": "string" }
            }
        }"#;

        let validator = SchemaValidator::from_json("test", schema).unwrap();
        let payload = serde_json::json!({"action_id": "abc"});
        let err = validator.validate("test", &payload).unwrap_err();
        assert!(err.errors.iter().any(|e| e.contains("tenant_id")));
    }

    #[test]
    fn unknown_schema_is_skipped() {
        let validator = SchemaValidator {
            schemas: HashMap::new(),
        };
        let payload = serde_json::json!({"anything": true});
        assert!(validator.validate("nonexistent", &payload).is_ok());
    }

    #[test]
    fn loads_from_snapshot_directory() {
        let snapshot_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("snapshots");
        if snapshot_dir.exists() {
            let validator = SchemaValidator::from_directory(&snapshot_dir).unwrap();
            let schemas = validator.loaded_schemas();
            assert!(!schemas.is_empty(), "Should load at least one schema");
            // All known schemas should be present
            assert!(schemas.contains(&"action_request"));
            assert!(schemas.contains(&"audit_event"));
        }
    }
}
