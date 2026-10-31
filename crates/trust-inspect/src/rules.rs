use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub keywords: Vec<String>,
    #[serde(default)]
    pub http_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialConfig {
    pub field_keys: Vec<String>,
    pub high_exposure_threshold_cents: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamConfig {
    pub contract_keywords: Vec<String>,
    pub contract_scope: String,
    pub finance_keywords: Vec<String>,
    pub finance_scope: String,
    pub iam_keywords: Vec<String>,
    pub iam_scope: String,
    pub destructive_scope: String,
    pub mutation_default_scope: String,
    pub read_default_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiConfig {
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRules {
    pub version: String,
    pub destructive: RuleConfig,
    pub mutation: RuleConfig,
    pub read: RuleConfig,
    pub financial: FinancialConfig,
    pub iam_scopes: IamConfig,
    pub pii: PiiConfig,
}

impl ClassificationRules {
    pub fn default_rules() -> Self {
        let toml_str = include_str!("classification_rules.toml");
        toml::from_str(toml_str).unwrap_or_else(|e| {
            panic!("Embedded classification_rules.toml is invalid: {e}");
        })
    }

    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }
}

