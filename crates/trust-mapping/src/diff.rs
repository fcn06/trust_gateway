use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmbiguityDossier {
    pub ambiguity_type: String, // "unit_mismatch", "field_name_divergence", "type_coercion", "missing_required"
    pub source_field: Option<String>,
    pub target_field: String,
    pub description: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaDiff {
    pub unmapped_source_fields: Vec<String>,
    pub missing_target_required: Vec<String>,
    pub matched_fields: Vec<String>,
    pub ambiguities: Vec<AmbiguityDossier>,
}

pub struct SchemaDiffer;

impl SchemaDiffer {
    pub fn diff(
        source_fields: &[String],
        target_fields: &[String],
        target_required: &[String],
        mapped_target_fields: &[String],
    ) -> SchemaDiff {
        let source_set: BTreeSet<&String> = source_fields.iter().collect();
        let target_set: BTreeSet<&String> = target_fields.iter().collect();
        let mapped_set: BTreeSet<&String> = mapped_target_fields.iter().collect();

        // 1. Missing target required fields
        let mut missing_target_required = Vec::new();
        for req in target_required {
            if !mapped_set.contains(req) {
                missing_target_required.push(req.clone());
            }
        }

        // 2. Unmapped source fields
        let mut unmapped_source_fields = Vec::new();
        for src in &source_set {
            if !mapped_set.contains(*src) {
                unmapped_source_fields.push((*src).clone());
            }
        }

        // 3. Matched fields
        let mut matched_fields = Vec::new();
        for tgt in &target_set {
            if mapped_set.contains(*tgt) {
                matched_fields.push((*tgt).clone());
            }
        }

        // 4. Ambiguity analysis
        let mut ambiguities = Vec::new();

        // Check for missing target required
        for req in &missing_target_required {
            ambiguities.push(AmbiguityDossier {
                ambiguity_type: "missing_required".to_string(),
                source_field: None,
                target_field: req.clone(),
                description: format!("Target required field '{req}' is not populated by the mapping IR."),
                recommended_action: format!("Add a MappingRule to populate '{req}' via Copy, Constant, or Scale."),
            });
        }

        // Check for unit mismatches (e.g. amount vs amount_cents)
        for src in source_fields {
            let s_lower = src.to_lowercase();
            for tgt in target_fields {
                let t_lower = tgt.to_lowercase();
                if s_lower.contains("amount") && t_lower.contains("amount_cents")
                    || s_lower.contains("cost") && t_lower.contains("cents")
                    || s_lower.contains("price") && t_lower.contains("cents")
                {
                    ambiguities.push(AmbiguityDossier {
                        ambiguity_type: "unit_mismatch".to_string(),
                        source_field: Some(src.clone()),
                        target_field: tgt.clone(),
                        description: format!(
                            "Potential financial unit mismatch between source '{src}' (likely major currency units/dollars) and target '{tgt}' (minor currency units/cents)."
                        ),
                        recommended_action: "Apply Scale operation with multiplier: 100.0".to_string(),
                    });
                }

                if (s_lower.contains("user_id") && t_lower.contains("account_id"))
                    || (s_lower.contains("account_id") && t_lower.contains("user_id"))
                {
                    ambiguities.push(AmbiguityDossier {
                        ambiguity_type: "field_name_divergence".to_string(),
                        source_field: Some(src.clone()),
                        target_field: tgt.clone(),
                        description: format!("Semantic field name divergence between source '{src}' and target '{tgt}'."),
                        recommended_action: "Verify identity boundary before binding user_id to account_id.".to_string(),
                    });
                }
            }
        }

        SchemaDiff {
            unmapped_source_fields,
            missing_target_required,
            matched_fields,
            ambiguities,
        }
    }
}
