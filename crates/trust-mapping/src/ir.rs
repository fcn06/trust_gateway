use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CastType {
    String,
    Integer,
    Float,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConcatPart {
    Literal { value: String },
    Field { from_path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MappingOp {
    Copy {
        from_path: String,
    },
    Constant {
        value: serde_json::Value,
    },
    Concat {
        parts: Vec<ConcatPart>,
    },
    Cast {
        from_path: String,
        target_type: CastType,
    },
    Scale {
        from_path: String,
        multiplier: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clamp_min: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clamp_max: Option<f64>,
    },
    LookupTable {
        from_path: String,
        table: HashMap<String, serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default_value: Option<serde_json::Value>,
    },
    ArrayMap {
        from_path: String,
        sub_rules: Vec<MappingRule>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MappingRule {
    pub target_path: String,
    #[serde(flatten)]
    pub operation: MappingOp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MappingRuleSet {
    pub mapping_id: String,
    pub version: String,
    pub source_schema: String,
    pub target_schema: String,
    pub rules: Vec<MappingRule>,
}

impl MappingRuleSet {
    pub fn compute_ir_hash(&self) -> String {
        let canonical_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        format!("{:x}", hasher.finalize())
    }
}

