use serde_json::json;
use std::collections::HashMap;
use trust_mapping::diff::SchemaDiffer;
use trust_mapping::interpreter::{Interpreter, InterpreterError};
use trust_mapping::ir::{CastType, ConcatPart, MappingOp, MappingRule, MappingRuleSet};
use trust_mapping::review_pack::ReviewPack;
use trust_mapping::verifier::VerificationHarness;

#[test]
fn test_interpreter_copy_constant_concat_cast_scale_lookup() {
    let mut lookup = HashMap::new();
    lookup.insert("US".to_string(), json!("United States"));
    lookup.insert("CA".to_string(), json!("Canada"));

    let rule_set = MappingRuleSet {
        mapping_id: "test_transform_01".to_string(),
        version: "1.0.0".to_string(),
        source_schema: "legacy_user@v1".to_string(),
        target_schema: "standard_customer@v2".to_string(),
        rules: vec![
            MappingRule {
                target_path: "customer.id".to_string(),
                operation: MappingOp::Copy {
                    from_path: "legacy_id".to_string(),
                },
            },
            MappingRule {
                target_path: "customer.tenant".to_string(),
                operation: MappingOp::Constant {
                    value: json!("enterprise_corp"),
                },
            },
            MappingRule {
                target_path: "customer.full_name".to_string(),
                operation: MappingOp::Concat {
                    parts: vec![
                        ConcatPart::Field {
                            from_path: "first_name".to_string(),
                        },
                        ConcatPart::Literal {
                            value: " ".to_string(),
                        },
                        ConcatPart::Field {
                            from_path: "last_name".to_string(),
                        },
                    ],
                },
            },
            MappingRule {
                target_path: "customer.age".to_string(),
                operation: MappingOp::Cast {
                    from_path: "age_str".to_string(),
                    target_type: CastType::Integer,
                },
            },
            MappingRule {
                target_path: "customer.balance_cents".to_string(),
                operation: MappingOp::Scale {
                    from_path: "balance_dollars".to_string(),
                    multiplier: 100.0,
                    clamp_min: Some(0.0),
                    clamp_max: None,
                },
            },
            MappingRule {
                target_path: "customer.country_name".to_string(),
                operation: MappingOp::LookupTable {
                    from_path: "country_code".to_string(),
                    table: lookup,
                    default_value: Some(json!("Unknown Country")),
                },
            },
        ],
    };

    let input = json!({
        "legacy_id": "usr_9988",
        "first_name": "Alice",
        "last_name": "Smith",
        "age_str": "35",
        "balance_dollars": 49.95,
        "country_code": "US"
    });

    let interpreter = Interpreter::default();
    let output = interpreter.execute(&rule_set, &input).unwrap();

    assert_eq!(output["customer"]["id"], "usr_9988");
    assert_eq!(output["customer"]["tenant"], "enterprise_corp");
    assert_eq!(output["customer"]["full_name"], "Alice Smith");
    assert_eq!(output["customer"]["age"], 35);
    assert_eq!(output["customer"]["balance_cents"], 4995);
    assert_eq!(output["customer"]["country_name"], "United States");
}

#[test]
fn test_interpreter_array_map_projection() {
    let rule_set = MappingRuleSet {
        mapping_id: "order_items_mapping".to_string(),
        version: "1.0.0".to_string(),
        source_schema: "legacy_order".to_string(),
        target_schema: "modern_order".to_string(),
        rules: vec![MappingRule {
            target_path: "items".to_string(),
            operation: MappingOp::ArrayMap {
                from_path: "raw_items".to_string(),
                sub_rules: vec![
                    MappingRule {
                        target_path: "sku".to_string(),
                        operation: MappingOp::Copy {
                            from_path: "item_code".to_string(),
                        },
                    },
                    MappingRule {
                        target_path: "unit_price_cents".to_string(),
                        operation: MappingOp::Scale {
                            from_path: "price".to_string(),
                            multiplier: 100.0,
                            clamp_min: None,
                            clamp_max: None,
                        },
                    },
                ],
            },
        }],
    };

    let input = json!({
        "raw_items": [
            { "item_code": "SKU-1", "price": 10.0 },
            { "item_code": "SKU-2", "price": 25.50 }
        ]
    });

    let interpreter = Interpreter::default();
    let output = interpreter.execute(&rule_set, &input).unwrap();

    let items = output["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["sku"], "SKU-1");
    assert_eq!(items[0]["unit_price_cents"], 1000);
    assert_eq!(items[1]["sku"], "SKU-2");
    assert_eq!(items[1]["unit_price_cents"], 2550);
}

#[test]
fn test_interpreter_fuel_exhaustion_fails_closed() {
    let rule_set = MappingRuleSet {
        mapping_id: "fuel_test".to_string(),
        version: "1.0.0".to_string(),
        source_schema: "a".to_string(),
        target_schema: "b".to_string(),
        rules: vec![
            MappingRule {
                target_path: "f1".to_string(),
                operation: MappingOp::Constant { value: json!(1) },
            },
            MappingRule {
                target_path: "f2".to_string(),
                operation: MappingOp::Constant { value: json!(2) },
            },
            MappingRule {
                target_path: "f3".to_string(),
                operation: MappingOp::Constant { value: json!(3) },
            },
        ],
    };

    // Give only 2 fuel units when 3 rules are executed
    let low_fuel_interpreter = Interpreter::new(2);
    let result = low_fuel_interpreter.execute(&rule_set, &json!({}));

    assert_eq!(result, Err(InterpreterError::FuelExhausted));
}

#[test]
fn test_schema_differ_and_ambiguity_detection() {
    let source_fields = vec!["vendor_id".to_string(), "amount".to_string(), "user_id".to_string()];
    let target_fields = vec!["vendor_id".to_string(), "amount_cents".to_string(), "account_id".to_string()];
    let target_required = vec!["vendor_id".to_string(), "amount_cents".to_string()];
    let mapped_target_fields = vec!["vendor_id".to_string()]; // amount_cents is missing from mapped!

    let diff = SchemaDiffer::diff(&source_fields, &target_fields, &target_required, &mapped_target_fields);

    assert_eq!(diff.missing_target_required, vec!["amount_cents"]);
    assert!(diff.ambiguities.iter().any(|a| a.ambiguity_type == "missing_required" && a.target_field == "amount_cents"));
    assert!(diff.ambiguities.iter().any(|a| a.ambiguity_type == "unit_mismatch" && a.target_field == "amount_cents"));
    assert!(diff.ambiguities.iter().any(|a| a.ambiguity_type == "field_name_divergence" && a.target_field == "account_id"));
}

#[test]
fn test_verification_harness_and_review_pack() {
    let rule_set = MappingRuleSet {
        mapping_id: "verify_pack_01".to_string(),
        version: "1.0.0".to_string(),
        source_schema: "in_v1".to_string(),
        target_schema: "out_v1".to_string(),
        rules: vec![MappingRule {
            target_path: "val".to_string(),
            operation: MappingOp::Copy { from_path: "raw".to_string() },
        }],
    };

    let vectors = vec![
        (json!({ "raw": "hello" }), json!({ "val": "hello" })),
        (json!({ "raw": "world" }), json!({ "val": "world" })),
    ];

    let harness = VerificationHarness::default();
    let report = harness.verify(&rule_set, &vectors);
    assert!(report.all_passed);
    assert_eq!(report.passed, 2);
    assert_eq!(report.failed, 0);

    let diff = SchemaDiffer::diff(&["raw".to_string()], &["val".to_string()], &["val".to_string()], &["val".to_string()]);
    let pack = ReviewPack::new(rule_set, diff, report);
    let md = pack.to_markdown();

    assert!(md.contains("Restricted Mapping Review Pack"));
    assert!(md.contains("✅ PASSED"));
    assert!(md.contains("Canonical IR SHA-256"));
}

