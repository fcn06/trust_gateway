use std::fs;
use std::path::Path;
use trust_inspect::openapi::OpenApiInspector;
use trust_inspect::synthesizer::ArtifactSynthesizer;

#[test]
fn test_corpus_100_percent_destructive_recall_gate() {
    let inspector = OpenApiInspector::default();
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");

    // 1. Hostile Spec
    let hostile_raw = fs::read_to_string(corpus_dir.join("hostile.json")).unwrap();
    let hostile_ops = inspector.inspect_spec_str(&hostile_raw).unwrap();

    let purge_op = hostile_ops.iter().find(|o| o.path == "/purge-all").expect("Found /purge-all");
    assert_eq!(purge_op.metrics.operation_kind, "destructive", "GET /purge-all must be classified as destructive despite GET verb!");
    assert_eq!(purge_op.recommended_action, "deny");
    assert_eq!(purge_op.metrics.reversibility, "Irreversible");

    let drop_op = hostile_ops.iter().find(|o| o.path == "/database/drop-tables").expect("Found drop-tables");
    assert_eq!(drop_op.metrics.operation_kind, "destructive", "GET /database/drop-tables must be classified as destructive!");
    assert_eq!(drop_op.recommended_action, "deny");

    let wipe_op = hostile_ops.iter().find(|o| o.path == "/users/{id}/wipe").expect("Found wipe");
    assert_eq!(wipe_op.metrics.operation_kind, "destructive", "POST /users/{{id}}/wipe must be classified as destructive!");
    assert_eq!(wipe_op.recommended_action, "deny");

    let status_del_op = hostile_ops.iter().find(|o| o.path == "/system/status").expect("Found status delete");
    assert_eq!(status_del_op.metrics.operation_kind, "destructive", "DELETE verb on /system/status must be caught as destructive!");

    // 2. Petstore CRUD Spec
    let petstore_raw = fs::read_to_string(corpus_dir.join("petstore_crud.json")).unwrap();
    let petstore_ops = inspector.inspect_spec_str(&petstore_raw).unwrap();
    let del_pet = petstore_ops.iter().find(|o| o.operation_id == "delete_pet").expect("Found delete_pet");
    assert_eq!(del_pet.metrics.operation_kind, "destructive");
    assert_eq!(del_pet.recommended_action, "deny");

    // 3. Cloud IAM Spec
    let iam_raw = fs::read_to_string(corpus_dir.join("cloud_iam.json")).unwrap();
    let iam_ops = inspector.inspect_spec_str(&iam_raw).unwrap();
    let revoke_all = iam_ops.iter().find(|o| o.operation_id == "revoke_all_credentials").expect("Found revoke_all");
    assert_eq!(revoke_all.metrics.operation_kind, "destructive");
    assert_eq!(revoke_all.recommended_action, "deny");

    // Destructive recall rate check: 0 false negatives
    let all_destructive: Vec<_> = hostile_ops
        .into_iter()
        .chain(petstore_ops.into_iter())
        .chain(iam_ops.into_iter())
        .filter(|o| o.metrics.operation_kind == "destructive")
        .collect();

    assert!(all_destructive.len() >= 6, "All 6 expected destructive endpoints across corpus must be caught!");
    for op in &all_destructive {
        assert_eq!(op.recommended_action, "deny", "Destructive endpoint {} must have recommended_action 'deny'", op.operation_id);
    }
}

#[test]
fn test_stripe_billing_pii_and_financial_classification() {
    let inspector = OpenApiInspector::default();
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let billing_raw = fs::read_to_string(corpus_dir.join("stripe_billing.json")).unwrap();
    let ops = inspector.inspect_spec_str(&billing_raw).unwrap();

    let charge_op = ops.iter().find(|o| o.operation_id == "create_charge").expect("Found create_charge");
    assert_eq!(charge_op.metrics.operation_kind, "mutation");
    assert_eq!(charge_op.recommended_action, "require_approval");
    assert!(charge_op.metrics.touched_iam_scopes.contains(&"finance:disburse".to_string()));
    assert!(charge_op.detected_pii_fields.contains(&"customer_email".to_string()));
    assert!(charge_op.detected_pii_fields.contains(&"card_number".to_string()));

    let list_op = ops.iter().find(|o| o.operation_id == "list_charges").expect("Found list_charges");
    assert_eq!(list_op.metrics.operation_kind, "read");
    assert_eq!(list_op.recommended_action, "allow");
}

#[test]
fn test_synthesizer_artifacts_generation() {
    let inspector = OpenApiInspector::default();
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let iam_raw = fs::read_to_string(corpus_dir.join("cloud_iam.json")).unwrap();
    let ops = inspector.inspect_spec_str(&iam_raw).unwrap();

    // 1. Generate Manifest
    let revoke_all = ops.iter().find(|o| o.operation_id == "revoke_all_credentials").unwrap();
    let manifest = ArtifactSynthesizer::generate_manifest(revoke_all, "cloud_iam", "did:web:enterprise:admin");
    assert_eq!(manifest.policy_defaults.default_tier, "tier3_deny");
    assert_eq!(manifest.policy_defaults.operation_kind, "destructive");

    // 2. Generate Policy Draft
    let policy_draft = ArtifactSynthesizer::generate_policy_draft(&ops, "cloud_iam");
    assert!(policy_draft.contains("action = \"deny\""));
    assert!(policy_draft.contains("action = \"require_approval\""));
    assert!(policy_draft.contains("lifecycle_state = \"probationary\""));

    // 3. Generate Onboarding Report
    let report = ArtifactSynthesizer::generate_onboarding_report(&ops, "cloud_iam", "cloud_iam.json");
    assert!(report.contains("Onboarding Security & Governance Dossier"));
    assert!(report.contains("Destructive Endpoints (Hard Deny)"));
}

#[test]
fn test_x_trust_annotations_v0_1() {
    let inspector = OpenApiInspector::default();
    let spec_json = r#"{
        "openapi": "3.0.0",
        "info": { "title": "Annotated API", "version": "1.0.0" },
        "paths": {
            "/payments/custom": {
                "post": {
                    "operationId": "custom_payment",
                    "summary": "Process payment",
                    "x-trust": {
                        "operation_kind": "mutation",
                        "is_idempotent": true,
                        "max_financial_exposure": 75000,
                        "data_origin_trust": "verified_partner",
                        "egress": {
                            "pii_scrub": true,
                            "schema_enforce": true
                        }
                    },
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    }"#;

    let ops = inspector.inspect_spec_str(spec_json).expect("spec parse failed");
    assert_eq!(ops.len(), 1);
    let op = &ops[0];
    assert_eq!(op.metrics.operation_kind, "mutation");
    assert!(op.metrics.is_idempotent);
    assert_eq!(op.metrics.financial_exposure_cents, 75000);
    assert!(!op.metrics.financial_indeterminate);
    assert_eq!(op.recommended_action, "require_approval");
}
