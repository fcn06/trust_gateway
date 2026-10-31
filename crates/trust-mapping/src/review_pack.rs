use crate::diff::SchemaDiff;
use crate::ir::MappingRuleSet;
use crate::verifier::VerificationReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReviewPack {
    pub mapping_id: String,
    pub ir_hash: String,
    pub rule_set: MappingRuleSet,
    pub diff: SchemaDiff,
    pub verification: VerificationReport,
}

impl ReviewPack {
    pub fn new(
        rule_set: MappingRuleSet,
        diff: SchemaDiff,
        verification: VerificationReport,
    ) -> Self {
        let ir_hash = rule_set.compute_ir_hash();
        let mapping_id = rule_set.mapping_id.clone();
        Self {
            mapping_id,
            ir_hash,
            rule_set,
            diff,
            verification,
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "# 📋 Restricted Mapping Review Pack: `{}`\n\n",
            self.mapping_id
        ));
        md.push_str(&format!("- **Canonical IR SHA-256:** `{}`\n", self.ir_hash));
        md.push_str(&format!(
            "- **Source Schema:** `{}` | **Target Schema:** `{}`\n\n",
            self.rule_set.source_schema, self.rule_set.target_schema
        ));

        md.push_str("## 1. Executive Summary\n\n");
        md.push_str("| Metric | Value |\n|---|---|\n");
        md.push_str(&format!("| **Total Mapping Rules** | `{}` |\n", self.rule_set.rules.len()));
        md.push_str(&format!(
            "| **Deterministic Verification** | `{}/{} passed` ({}) |\n",
            self.verification.passed,
            self.verification.total_vectors,
            if self.verification.all_passed { "✅ PASSED" } else { "❌ FAILED" }
        ));
        md.push_str(&format!(
            "| **Detected Ambiguities** | `{}` |\n",
            self.diff.ambiguities.len()
        ));
        md.push_str(&format!(
            "| **Missing Target Required** | `{}` |\n\n",
            self.diff.missing_target_required.len()
        ));

        if !self.diff.ambiguities.is_empty() {
            md.push_str("## 2. ⚠️ Ambiguity Warnings & Unit Discrepancies\n\n");
            md.push_str("| Type | Source Field | Target Field | Description | Recommended Remediation |\n");
            md.push_str("|---|---|---|---|---|\n");
            for amb in &self.diff.ambiguities {
                md.push_str(&format!(
                    "| `{}` | `{}` | `{}` | {} | **{}** |\n",
                    amb.ambiguity_type,
                    amb.source_field.as_deref().unwrap_or("N/A"),
                    amb.target_field,
                    amb.description,
                    amb.recommended_action
                ));
            }
            md.push('\n');
        }

        md.push_str("## 3. Mapping Rules Specification\n\n");
        md.push_str("```json\n");
        md.push_str(&serde_json::to_string_pretty(&self.rule_set).unwrap_or_default());
        md.push_str("\n```\n\n");

        md.push_str("## 4. Verification Test Results\n\n");
        if self.verification.all_passed {
            md.push_str("All deterministic test vectors matched expected target values with 0 fuel exhaustion errors.\n");
        } else {
            md.push_str("### ❌ Failures:\n\n");
            for fail in &self.verification.failures {
                md.push_str(&format!(
                    "- Vector #{}: Error: {}\n",
                    fail.vector_index,
                    fail.error_message.as_deref().unwrap_or("Mismatch")
                ));
            }
        }

        md
    }
}
