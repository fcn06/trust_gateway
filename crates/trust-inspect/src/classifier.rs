use crate::rules::ClassificationRules;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeterministicMetrics {
    pub schema_verified: bool,
    pub is_mutation: bool,
    pub operation_kind: String, // "read", "mutation", "destructive"
    pub financial_exposure_cents: u64,
    pub financial_indeterminate: bool,
    pub touched_iam_scopes: Vec<String>,
    pub reversibility: String, // "Irreversible", "AuditedJournal", "N/A - Read-Only"
    pub is_idempotent: bool,
    pub projected_fields: Vec<String>,
    pub risk_classification: String, // "Low", "Medium", "High", "Critical"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassifiedOperation {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub metrics: DeterministicMetrics,
    pub detected_pii_fields: Vec<String>,
    pub required_params: Vec<String>,
    pub recommended_action: String, // "deny", "require_approval", "allow"
}

pub struct OperationClassifier {
    rules: ClassificationRules,
}

impl Default for OperationClassifier {
    fn default() -> Self {
        Self::new(ClassificationRules::default_rules())
    }
}

impl OperationClassifier {
    pub fn new(rules: ClassificationRules) -> Self {
        Self { rules }
    }

    pub fn inspect(
        &self,
        tool_name: &str,
        operation_kind: &str,
        arguments: &Value,
        skill_manifest: Option<&Value>,
    ) -> DeterministicMetrics {
        let tool_lower = tool_name.trim().to_lowercase();
        let op_lower = operation_kind.trim().to_lowercase();

        // 1. Manifest-backed inspection if provided
        let manifest_op = skill_manifest
            .and_then(|m| m.get("policy_defaults"))
            .and_then(|pd| pd.get("operation_kind"))
            .and_then(|op| op.as_str())
            .map(|s| s.to_lowercase());

        let effective_op_declared = manifest_op.unwrap_or_else(|| op_lower.clone());

        // 2. Destructive detection (100% Destructive Recall Gate: keywords in name or declared op)
        let is_destructive = effective_op_declared == "destructive"
            || self
                .rules
                .destructive
                .keywords
                .iter()
                .any(|kw| tool_lower.contains(kw));

        // 3. Mutation detection
        let is_mutation = is_destructive
            || effective_op_declared == "write"
            || effective_op_declared == "mutation"
            || effective_op_declared == "update"
            || effective_op_declared == "create"
            || effective_op_declared == "amend"
            || effective_op_declared == "execute"
            || effective_op_declared == "post"
            || effective_op_declared == "put"
            || effective_op_declared == "patch"
            || (effective_op_declared != "read"
                && effective_op_declared != "get"
                && self
                    .rules
                    .mutation
                    .keywords
                    .iter()
                    .any(|kw| tool_lower.contains(kw)));

        let operation_kind_resolved = if is_destructive {
            "destructive".to_string()
        } else if is_mutation {
            "mutation".to_string()
        } else {
            "read".to_string()
        };

        let is_idempotent = !is_mutation
            && (operation_kind_resolved == "read"
                || self
                    .rules
                    .read
                    .keywords
                    .iter()
                    .any(|kw| tool_lower.starts_with(kw)));

        let reversibility = if is_destructive {
            "Irreversible".to_string()
        } else if is_mutation {
            "AuditedJournal".to_string()
        } else {
            "N/A - Read-Only".to_string()
        };

        // 4. Deterministic financial extraction
        let (financial_exposure_cents, financial_indeterminate) =
            self.extract_deterministic_financials(arguments);

        // 5. IAM Scope Mapping
        let mut touched_iam_scopes = Vec::new();
        if operation_kind_resolved != "read"
            && self
                .rules
                .iam_scopes
                .contract_keywords
                .iter()
                .any(|kw| tool_lower.contains(kw))
        {
            touched_iam_scopes.push(self.rules.iam_scopes.contract_scope.clone());
        }
        if financial_exposure_cents > 0
            || (operation_kind_resolved != "read"
                && self
                    .rules
                    .iam_scopes
                    .finance_keywords
                    .iter()
                    .any(|kw| tool_lower.contains(kw)))
        {
            touched_iam_scopes.push(self.rules.iam_scopes.finance_scope.clone());
        }
        if self
            .rules
            .iam_scopes
            .iam_keywords
            .iter()
            .any(|kw| tool_lower.contains(kw))
        {
            touched_iam_scopes.push(self.rules.iam_scopes.iam_scope.clone());
        }
        if is_destructive {
            touched_iam_scopes.push(self.rules.iam_scopes.destructive_scope.clone());
        }
        if touched_iam_scopes.is_empty() {
            if is_mutation {
                touched_iam_scopes.push(self.rules.iam_scopes.mutation_default_scope.clone());
            } else {
                touched_iam_scopes.push(self.rules.iam_scopes.read_default_scope.clone());
            }
        }
        touched_iam_scopes.sort();
        touched_iam_scopes.dedup();

        // 6. Projected Fields
        let projected_fields = self.extract_projected_fields(arguments);

        // 7. Risk classification
        let risk_classification = if is_destructive {
            "Critical".to_string()
        } else if financial_exposure_cents > self.rules.financial.high_exposure_threshold_cents
            || financial_indeterminate
        {
            "High".to_string()
        } else if is_mutation || financial_exposure_cents > 0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };

        DeterministicMetrics {
            schema_verified: skill_manifest.is_some(),
            is_mutation,
            operation_kind: operation_kind_resolved,
            financial_exposure_cents,
            financial_indeterminate,
            touched_iam_scopes,
            reversibility,
            is_idempotent,
            projected_fields,
            risk_classification,
        }
    }

    pub fn extract_deterministic_financials(&self, args: &Value) -> (u64, bool) {
        let mut total_cents = 0u64;
        let mut indeterminate = false;

        if let Value::Object(map) = args {
            for key in &self.rules.financial.field_keys {
                if let Some(val) = map.get(key) {
                    match val {
                        Value::Number(n) => {
                            if let Some(u) = n.as_u64() {
                                if key == "amount_cents" {
                                    total_cents = total_cents.saturating_add(u);
                                } else {
                                    total_cents = total_cents.saturating_add(u.saturating_mul(100));
                                }
                            } else if let Some(f) = n.as_f64() {
                                if f >= 0.0 {
                                    total_cents = total_cents.saturating_add((f * 100.0) as u64);
                                } else {
                                    indeterminate = true;
                                }
                            }
                        }
                        Value::String(s) => {
                            let clean =
                                s.trim_start_matches(['$', '€', '£', '¥', ' ']).replace(',', "");
                            if let Ok(parsed) = clean.parse::<f64>() {
                                if parsed >= 0.0 {
                                    total_cents = total_cents.saturating_add((parsed * 100.0) as u64);
                                } else {
                                    indeterminate = true;
                                }
                            } else {
                                indeterminate = true;
                            }
                        }
                        Value::Array(_) | Value::Object(_) => {
                            indeterminate = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        (total_cents, indeterminate)
    }

    pub fn extract_projected_fields(&self, args: &Value) -> Vec<String> {
        let mut fields = Vec::new();
        if let Value::Object(map) = args {
            let priority_keys = [
                "vendor_id", "id", "contract_id", "account_id", "user_id",
                "amount", "amount_cents", "price", "months", "change",
                "target", "destination", "recipient", "role",
            ];

            for key in priority_keys {
                if map.contains_key(key) && !fields.contains(&key.to_string()) {
                    fields.push(key.to_string());
                }
            }

            if map.len() <= 6 {
                for key in map.keys() {
                    if !fields.contains(key) {
                        fields.push(key.clone());
                    }
                }
            }
        }
        fields.sort();
        fields
    }

    pub fn detect_pii_fields(&self, fields: &[String]) -> Vec<String> {
        let mut detected = Vec::new();
        for field in fields {
            let f_lower = field.to_lowercase();
            if self
                .rules
                .pii
                .patterns
                .iter()
                .any(|pat| f_lower.contains(pat))
            {
                detected.push(field.clone());
            }
        }
        detected.sort();
        detected.dedup();
        detected
    }
}
