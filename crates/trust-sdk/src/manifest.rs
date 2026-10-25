use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum DataOriginTrust {
    TrustedInternal = 0,
    VerifiedPartner = 1,
    #[default]
    UntrustedExternal = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArgumentLineageRule {
    pub argument_name: String,
    pub must_originate_from: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeType {
    #[default]
    NativeTool,
    SandboxedWasm,
    BoundedHttp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSpec {
    pub runtime: RuntimeType,
    pub entrypoint: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
    #[serde(default = "default_memory_limit_mb")]
    pub memory_limit_mb: u32,
    #[serde(default = "default_allowed_interpreters")]
    pub allowed_interpreters: Vec<String>,
}

fn default_timeout_secs() -> u32 {
    30
}

fn default_memory_limit_mb() -> u32 {
    512
}

fn default_allowed_interpreters() -> Vec<String> {
    vec!["bash".to_string(), "sh".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDefaults {
    #[serde(default = "default_tier")]
    pub default_tier: String,
    #[serde(default = "default_max_freq")]
    pub max_frequency_per_trace: u32,
    #[serde(default = "default_risk")]
    pub default_risk_level: String,
    #[serde(default = "default_operation_kind")]
    pub operation_kind: String,
}

fn default_tier() -> String {
    "tier0_auto".to_string()
}

fn default_max_freq() -> u32 {
    3
}

fn default_risk() -> String {
    "low".to_string()
}

fn default_operation_kind() -> String {
    "read".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressClassification {
    #[serde(default)]
    pub contains_pii: bool,
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    #[serde(default)]
    pub allowed_fields: Vec<String>,
}

fn default_max_payload_bytes() -> usize {
    65536
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author_did: String,
    #[serde(default)]
    pub data_origin_trust: DataOriginTrust,
    #[serde(default)]
    pub lineage_rules: Vec<ArgumentLineageRule>,
    pub execution: ExecutionSpec,
    pub input_schema: serde_json::Value,
    pub policy_defaults: PolicyDefaults,
    pub egress: EgressClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteSkillPublication {
    pub manifest: SkillManifest,
    pub provider_did: String,
    pub endpoint_url: String,
    pub proof_signature: String,
    pub capabilities_ucan: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestValidationError {
    #[error("Invalid schema version: expected 'lianxi.skill/v1', got '{0}'")]
    InvalidSchemaVersion(String),

    #[error("Invalid skill ID '{0}': must conform to reverse-DNS naming (^io\\.lianxi\\.[a-z0-9_.-]+@v[0-9]+$)")]
    InvalidSkillId(String),

    #[error("Invalid skill name '{0}': must match ^[a-z0-9_]{{3,32}}$")]
    InvalidSkillName(String),

    #[error("Invalid entrypoint '{0}': path traversal is strictly prohibited")]
    PathTraversal(String),

    #[error("Endpoint URL must use https scheme: '{0}'")]
    InsecureEndpointUrl(String),

    #[error("Operation kind must be explicitly specified for non-read operations: '{0}'")]
    UnspecifiedOperationKind(String),
}

impl SkillManifest {
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if self.schema_version != "lianxi.skill/v1" {
            return Err(ManifestValidationError::InvalidSchemaVersion(
                self.schema_version.clone(),
            ));
        }

        if !is_valid_skill_id(&self.id) {
            return Err(ManifestValidationError::InvalidSkillId(self.id.clone()));
        }

        if !is_valid_skill_name(&self.name) {
            return Err(ManifestValidationError::InvalidSkillName(self.name.clone()));
        }

        let entrypoint = &self.execution.entrypoint;
        if entrypoint.starts_with('/')
            || entrypoint.starts_with('\\')
            || entrypoint.contains("..")
            || Path::new(entrypoint).is_absolute()
        {
            return Err(ManifestValidationError::PathTraversal(entrypoint.clone()));
        }

        let op = self.policy_defaults.operation_kind.to_lowercase();
        if op != "read" && op.is_empty() {
            return Err(ManifestValidationError::UnspecifiedOperationKind(
                self.policy_defaults.operation_kind.clone(),
            ));
        }

        Ok(())
    }
}

impl RemoteSkillPublication {
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        self.manifest.validate()?;

        if !self.endpoint_url.starts_with("https://") {
            return Err(ManifestValidationError::InsecureEndpointUrl(
                self.endpoint_url.clone(),
            ));
        }

        Ok(())
    }
}

fn is_valid_skill_id(id: &str) -> bool {
    // ^io\.lianxi\.[a-z0-9_.-]+@v[0-9]+$
    if !id.starts_with("io.lianxi.") {
        return false;
    }
    let parts: Vec<&str> = id.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix = parts[0];
    let version = parts[1];
    if !version.starts_with('v') || version.len() < 2 {
        return false;
    }
    if !version[1..].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let sub = &prefix["io.lianxi.".len()..];
    if sub.is_empty() {
        return false;
    }
    sub.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-')
}

fn is_valid_skill_name(name: &str) -> bool {
    // ^[a-z0-9_]{3,32}$
    if name.len() < 3 || name.len() > 32 {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> SkillManifest {
        SkillManifest {
            schema_version: "lianxi.skill/v1".to_string(),
            id: "io.lianxi.skill.weather@v1".to_string(),
            name: "claw_weather".to_string(),
            version: "1.0.0".to_string(),
            description: "Get weather".to_string(),
            author_did: "did:web:lianxi.io".to_string(),
            data_origin_trust: DataOriginTrust::TrustedInternal,
            lineage_rules: vec![],
            execution: ExecutionSpec {
                runtime: RuntimeType::NativeTool,
                entrypoint: "run.sh".to_string(),
                timeout_secs: 30,
                memory_limit_mb: 512,
                allowed_interpreters: vec!["bash".to_string()],
            },
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "city": { "type": "string" } }
            }),
            policy_defaults: PolicyDefaults {
                default_tier: "tier0_auto".to_string(),
                max_frequency_per_trace: 3,
                default_risk_level: "low".to_string(),
                operation_kind: "read".to_string(),
            },
            egress: EgressClassification {
                contains_pii: false,
                max_payload_bytes: 65536,
                allowed_fields: vec!["temp".to_string()],
            },
        }
    }

    #[test]
    fn test_valid_manifest() {
        let m = valid_manifest();
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_invalid_schema_version() {
        let mut m = valid_manifest();
        m.schema_version = "v1".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestValidationError::InvalidSchemaVersion(_))
        ));
    }

    #[test]
    fn test_invalid_id() {
        let mut m = valid_manifest();
        m.id = "bad_id".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestValidationError::InvalidSkillId(_))
        ));
    }

    #[test]
    fn test_invalid_name() {
        let mut m = valid_manifest();
        m.name = "A-B!".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestValidationError::InvalidSkillName(_))
        ));
    }

    #[test]
    fn test_path_traversal_rejection() {
        let mut m = valid_manifest();
        m.execution.entrypoint = "../evil.sh".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestValidationError::PathTraversal(_))
        ));

        m.execution.entrypoint = "/etc/passwd".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestValidationError::PathTraversal(_))
        ));
    }

    #[test]
    fn test_remote_publication_https_check() {
        let m = valid_manifest();
        let pub_insecure = RemoteSkillPublication {
            manifest: m.clone(),
            provider_did: "did:web:provider.com".to_string(),
            endpoint_url: "http://insecure.provider.com/call".to_string(),
            proof_signature: "sig".to_string(),
            capabilities_ucan: None,
        };
        assert!(matches!(
            pub_insecure.validate(),
            Err(ManifestValidationError::InsecureEndpointUrl(_))
        ));

        let pub_secure = RemoteSkillPublication {
            manifest: m,
            provider_did: "did:web:provider.com".to_string(),
            endpoint_url: "https://secure.provider.com/call".to_string(),
            proof_signature: "sig".to_string(),
            capabilities_ucan: None,
        };
        assert!(pub_secure.validate().is_ok());
    }

    #[test]
    fn test_unknown_field_rejection() {
        let json = serde_json::json!({
            "schema_version": "lianxi.skill/v1",
            "id": "io.lianxi.skill.weather@v1",
            "name": "claw_weather",
            "version": "1.0.0",
            "description": "test",
            "author_did": "did:web:lianxi.io",
            "unknown_extra_field": 123,
            "execution": {
                "runtime": "native_tool",
                "entrypoint": "run.sh"
            },
            "input_schema": {},
            "policy_defaults": {},
            "egress": {}
        });

        let parsed: Result<SkillManifest, _> = serde_json::from_value(json);
        assert!(parsed.is_err());
    }
}
