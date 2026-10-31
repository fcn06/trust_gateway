use crate::interpreter::Interpreter;
use crate::ir::MappingRuleSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorFailure {
    pub vector_index: usize,
    pub input: Value,
    pub expected: Value,
    pub actual: Option<Value>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub total_vectors: usize,
    pub passed: usize,
    pub failed: usize,
    pub all_passed: bool,
    pub failures: Vec<VectorFailure>,
    pub ir_hash: String,
}

pub struct VerificationHarness {
    interpreter: Interpreter,
}

impl Default for VerificationHarness {
    fn default() -> Self {
        Self::new(Interpreter::default())
    }
}

impl VerificationHarness {
    pub fn new(interpreter: Interpreter) -> Self {
        Self { interpreter }
    }

    pub fn verify(
        &self,
        rule_set: &MappingRuleSet,
        test_vectors: &[(Value, Value)],
    ) -> VerificationReport {
        let total = test_vectors.len();
        let mut passed = 0;
        let mut failures = Vec::new();

        for (idx, (input, expected)) in test_vectors.iter().enumerate() {
            match self.interpreter.execute(rule_set, input) {
                Ok(actual) => {
                    if &actual == expected {
                        passed += 1;
                    } else {
                        failures.push(VectorFailure {
                            vector_index: idx,
                            input: input.clone(),
                            expected: expected.clone(),
                            actual: Some(actual),
                            error_message: Some("Output value mismatch".to_string()),
                        });
                    }
                }
                Err(e) => {
                    failures.push(VectorFailure {
                        vector_index: idx,
                        input: input.clone(),
                        expected: expected.clone(),
                        actual: None,
                        error_message: Some(e.to_string()),
                    });
                }
            }
        }

        let all_passed = passed == total;
        let ir_hash = rule_set.compute_ir_hash();

        VerificationReport {
            total_vectors: total,
            passed,
            failed: failures.len(),
            all_passed,
            failures,
            ir_hash,
        }
    }
}

