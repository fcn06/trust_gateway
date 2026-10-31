use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use jwt_simple::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tower::ServiceExt;
use trust_engine::approval::{ApprovalManager, NoopApprovalNotifier};
use trust_engine::auth::ApiKeyAuthenticator;
use trust_engine::egress::EgressProcessor;
use trust_engine::local_adapters::basic_taint::BasicBinaryTaintTracker;
use trust_engine::local_adapters::local_runner::LocalSubprocessDispatcher;
use trust_engine::local_adapters::memory_nonce::InMemoryNonceStore;
use trust_engine::local_adapters::sqlite_audit::SqliteAuditSink;
use trust_engine::local_adapters::static_registry::StaticSkillRegistry;
use trust_engine::policy::PolicyEngine;
use trust_engine::traits::*;
use trust_engine::{DefaultReputationEvaluator, DefaultSettlementEngine, TenancyMode, TrustEngine};
use trust_gateway_oss::*;
use trust_sdk::canonical::canonical_hash;
use trust_sdk::grants::{sign_grant_jwt, validate_bound, ExecutionGrant, GrantClearance};
use trust_sdk::manifest::*;
use trust_sdk::model::{ProposedAction, TrustEnvelope};

async fn setup_test_engine() -> (Arc<TrustEngine>, Arc<SqliteAuditSink>) {
    let key_pair = Ed25519KeyPair::generate();
    let policy_toml = r#"
[governance]
policy_version = "1.0.0"
default_action = "deny"
input_hash_binding_required = true
max_grant_ttl_seconds = 30

[[rules]]
name = "Auto-allow read-only operations"
operation_kind = "read"
action = "allow"
priority = 10

[[rules]]
name = "Require approval for mutations"
operation_kind = "write"
action = "require_approval"
priority = 20
"#;
    let policy_engine = Arc::new(PolicyEngine::from_toml(policy_toml).unwrap());
    let native_tools_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../native_tools");
    let static_registry = Arc::new(StaticSkillRegistry::new(native_tools_dir, false));
    static_registry.load_all().await.unwrap();

    // Register a mutation tool for taint testing
    let mutation_manifest = SkillManifest {
        schema_version: "lianxi.skill/v1".to_string(),
        id: "io.lianxi.skill.mutation_tool@v1".to_string(),
        name: "claw_mutation_tool".to_string(),
        version: "1.0.0".to_string(),
        description: "A state-modifying mutation tool".to_string(),
        author_did: "did:web:lianxi.io".to_string(),
        data_origin_trust: DataOriginTrust::TrustedInternal,
        lineage_rules: vec![],
        execution: ExecutionSpec {
            runtime: RuntimeType::NativeTool,
            entrypoint: "run.sh".to_string(),
            timeout_secs: 10,
            memory_limit_mb: 256,
            allowed_interpreters: vec!["bash".to_string()],
        },
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "data": { "type": "string" } }
        }),
        policy_defaults: PolicyDefaults {
            default_tier: "tier0_auto".to_string(),
            max_frequency_per_trace: 5,
            default_risk_level: "medium".to_string(),
            operation_kind: "write".to_string(),
        },
        egress: EgressClassification {
            contains_pii: false,
            max_payload_bytes: 65536,
            allowed_fields: vec![],
        },
    };
    static_registry
        .register_skill_direct(mutation_manifest)
        .await;

    let audit_sink = Arc::new(SqliteAuditSink::in_memory().unwrap());
    let approval_manager = Arc::new(ApprovalManager::new(Arc::new(NoopApprovalNotifier)));
    let nonce_store = Arc::new(InMemoryNonceStore::new());
    let taint_lineage_engine = Arc::new(BasicBinaryTaintTracker::new());
    let reputation_evaluator = Arc::new(DefaultReputationEvaluator);
    let settlement_engine = Arc::new(DefaultSettlementEngine);
    let dispatcher = Arc::new(LocalSubprocessDispatcher::new(native_tools_dir));

    let engine = Arc::new(TrustEngine {
        tenancy_mode: TenancyMode::Single,
        signing_key_pair: key_pair,
        root_verifying_key: None,
        token_verifier: None,
        policy_engine,
        skill_registry: static_registry,
        nonce_store,
        taint_lineage_engine,
        reputation_evaluator,
        settlement_engine,
        dispatcher,
        audit_sink: audit_sink.clone(),
        approval_manager,
        contract_registry: Arc::new(trust_engine::local_adapters::memory_contract::InMemoryContractRegistry::new()),
        tracked_call_chains: Arc::new(RwLock::new(HashMap::new())),
        configured_api_keys: vec!["sk_test_dev_key".to_string()],
    });

    (engine, audit_sink)
}

#[tokio::test]
async fn test_conformance_scenario_1_zero_infra_boot_mcp_pii_audit_tenancy() {
    let (engine, audit_sink) = setup_test_engine().await;

    let state = Arc::new(AppState {
        engine: engine.clone(),
        start_time: Instant::now(),
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });

    let app = build_app(state, 65536);

    // 1. MCP SSE connection initializes and receives endpoint event
    let req = Request::builder()
        .method("GET")
        .uri("/v1/mcp/sse")
        .header(header::AUTHORIZATION, "Bearer sk_test_dev_key")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    // 2. Propose action via MCP tools/call (claw_weather)
    let call_req = Request::builder()
        .method("POST")
        .uri("/v1/mcp/messages")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_test_dev_key")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "claw_weather",
                    "arguments": { "location": "San Francisco" }
                }
            }))
            .unwrap(),
        ))
        .unwrap();

    let call_resp = app.clone().oneshot(call_req).await.unwrap();
    assert_eq!(call_resp.status(), StatusCode::OK);

    // 3. Egress PII redaction test
    let pii_input = serde_json::json!({
        "contact": "Contact security@example.com or use api key sk-abcdef1234567890123456",
        "data": "normal info"
    });
    let egress_spec = EgressClassification {
        contains_pii: true,
        max_payload_bytes: 65536,
        allowed_fields: vec!["contact".to_string(), "data".to_string()],
    };
    let scrubbed = EgressProcessor::process_egress(&pii_input, &egress_spec).unwrap();
    let scrubbed_str = scrubbed["contact"].as_str().unwrap();
    assert!(!scrubbed_str.contains("security@example.com"));
    assert!(!scrubbed_str.contains("sk-abcdef1234567890123456"));
    assert!(scrubbed_str.contains("[REDACTED]"));

    // 4. Audit hash chain verifies
    let count = audit_sink.verify_chain().expect("Audit chain must verify");
    assert!(
        count >= 2,
        "Expected at least 2 audit events, found {}",
        count
    );

    // 5. Tenancy guard: X-Tenant-ID: acme -> 403 Forbidden
    let bad_tenant_req = Request::builder()
        .method("POST")
        .uri("/v1/mcp/messages")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_test_dev_key")
        .header("X-Tenant-ID", "acme")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "claw_weather",
                    "arguments": { "location": "Boston" }
                }
            }))
            .unwrap(),
        ))
        .unwrap();

    let bad_resp = app.clone().oneshot(bad_tenant_req).await.unwrap();
    assert_eq!(bad_resp.status(), StatusCode::FORBIDDEN);

    // Also verify REST propose returns 403 for acme
    let rest_bad_tenant_req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_test_dev_key")
        .header("X-Tenant-ID", "acme")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "action_id": "act_test_acme",
                "tool_name": "claw_weather",
                "arguments": { "location": "Boston" },
                "tenant_id": "acme"
            }))
            .unwrap(),
        ))
        .unwrap();

    let rest_bad_resp = app.oneshot(rest_bad_tenant_req).await.unwrap();
    assert_eq!(rest_bad_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_conformance_scenario_2_taint_propagation_and_downgrade() {
    let (engine, _) = setup_test_engine().await;
    let trace_id = "trace_taint_flow_123";

    // 1. Call untrusted tool claw_extract_content_from_url
    let untrusted_skill = engine
        .skill_registry
        .get_skill("default", "claw_extract_content_from_url")
        .await
        .unwrap()
        .expect("claw_extract_content_from_url must exist");

    assert_eq!(
        untrusted_skill.data_origin_trust,
        DataOriginTrust::UntrustedExternal
    );

    // Record untrusted output in trace
    engine
        .taint_lineage_engine
        .record_tool_output(
            "default",
            trace_id,
            &untrusted_skill,
            &serde_json::json!({ "extracted": "malicious prompt injection" }),
        )
        .await
        .unwrap();

    // 2. Propose a mutation in the tainted trace
    let mutation_action = ProposedAction {
        action_id: "act_mutation_1".to_string(),
        tool_name: "claw_mutation_tool".to_string(),
        arguments: serde_json::json!({ "data": "update database" }),
        tenant_id: "default".to_string(),
        workspace_id: "default".to_string(),
        ..Default::default()
    };

    let envelope = TrustEnvelope {
        trace_id: trace_id.to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        payload: mutation_action,
    };

    let result = engine
        .propose_and_execute("Bearer sk_test_dev_key", envelope)
        .await;

    // Must be downgraded to require human approval
    match result {
        Err(EngineError::ApprovalRequired { reason, .. }) => {
            assert!(
                reason.contains("taint_escalation_untrusted_context")
                    || reason.contains("human_approval")
            );
        }
        other => panic!(
            "Expected ApprovalRequired due to taint downgrade, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_conformance_scenario_3_security_regressions() {
    let key_pair = Ed25519KeyPair::generate();
    let now = chrono::Utc::now().timestamp();
    let valid_args = serde_json::json!({ "param": "value123" });
    let input_hash = canonical_hash(&valid_args);

    let grant = ExecutionGrant {
        jti: "jti_test_regress_1".to_string(),
        action_id: "act_regress_1".to_string(),
        tenant_id: "default".to_string(),
        workspace_id: "ws_default".to_string(),
        tool_name: "claw_weather".to_string(),
        input_hash,
        iss: "trust_gateway".to_string(),
        exp: now + 30,
        policy_fingerprint: "fp_test".to_string(),
        clearance: GrantClearance::default(),
        economic_claim: None,
        budget: None,
        contract_id: None,
        contract_hash: None,
        source_input_hash: None,
        lineage_attestation: None,
    };

    let grant_jwt = sign_grant_jwt(&grant, "executor-host", &key_pair).unwrap();
    let pub_key = key_pair.public_key();

    // 1. Tampered input_hash rejected
    let tampered_args = serde_json::json!({ "param": "hacked_value" });
    let res_tampered = validate_bound(
        &grant_jwt,
        "claw_weather",
        &tampered_args,
        "executor-host",
        &pub_key,
    );
    assert!(
        res_tampered.is_err(),
        "Tampered input_hash must be rejected"
    );

    // 2. Wrong audience rejected
    let res_wrong_aud = validate_bound(
        &grant_jwt,
        "claw_weather",
        &valid_args,
        "did:web:wrong-provider.com",
        &pub_key,
    );
    assert!(res_wrong_aud.is_err(), "Wrong audience must be rejected");

    // 3. Replayed jti rejected
    let nonce_store = InMemoryNonceStore::new();
    assert!(nonce_store
        .consume_nonce("default", "jti_replay_test", 30)
        .await
        .is_ok());
    let res_replay = nonce_store
        .consume_nonce("default", "jti_replay_test", 30)
        .await;
    assert!(
        matches!(res_replay, Err(EngineError::ReplayDetected(_))),
        "Replayed JTI must be rejected"
    );

    // 4. Oversize payload strictly rejected
    let oversize_data = serde_json::json!({ "blob": "x".repeat(70000) });
    let egress_spec = EgressClassification {
        contains_pii: false,
        max_payload_bytes: 65536,
        allowed_fields: vec![],
    };
    let res_oversize = EgressProcessor::process_egress(&oversize_data, &egress_spec);
    assert!(
        matches!(res_oversize, Err(EngineError::EgressPayloadTooLarge { .. })),
        "Oversize payload must be rejected"
    );

    // 5. Path traversal manifest rejected
    let bad_manifest_json = serde_json::json!({
        "schema_version": "lianxi.skill/v1",
        "id": "io.lianxi.skill.traversal@v1",
        "name": "claw_traversal",
        "version": "1.0.0",
        "description": "Path traversal exploit",
        "author_did": "did:web:evil.com",
        "execution": {
            "runtime": "native_tool",
            "entrypoint": "../../etc/passwd",
            "timeout_secs": 10,
            "memory_limit_mb": 256,
            "allowed_interpreters": ["bash"]
        },
        "input_schema": {},
        "policy_defaults": {
            "default_tier": "tier0_auto",
            "max_frequency_per_trace": 1,
            "default_risk_level": "high"
        },
        "egress": {
            "contains_pii": false,
            "max_payload_bytes": 65536,
            "allowed_fields": []
        }
    });

    let manifest_res: Result<SkillManifest, _> = serde_json::from_value(bad_manifest_json);
    if let Ok(m) = manifest_res {
        assert!(
            m.validate().is_err(),
            "Path traversal entrypoint must fail validation"
        );
    }
}

#[tokio::test]
async fn test_conformance_scenario_4_api_key_authentication_and_admin_approval() {
    let key_pair = Ed25519KeyPair::generate();
    let policy_toml = r#"
[governance]
policy_version = "1.0.0"
default_action = "deny"

[[rules]]
name = "Standard reads"
operation_kind = "read"
action = "allow"
priority = 10

[[rules]]
name = "Mutation tool requires human approval"
tool_names = ["claw_mutation_tool"]
action = "require_approval"
priority = 100
"#;
    let policy_engine = Arc::new(PolicyEngine::from_toml(policy_toml).unwrap());
    let native_tools_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../native_tools");
    let static_registry = Arc::new(StaticSkillRegistry::new(native_tools_dir, false));
    static_registry.load_all().await.unwrap();

    let mutation_manifest = SkillManifest {
        schema_version: "lianxi.skill/v1".to_string(),
        id: "io.lianxi.skill.mutation_tool@v1".to_string(),
        name: "claw_mutation_tool".to_string(),
        version: "1.0.0".to_string(),
        description: "A state-modifying mutation tool".to_string(),
        author_did: "did:web:lianxi.io".to_string(),
        data_origin_trust: DataOriginTrust::TrustedInternal,
        lineage_rules: vec![],
        execution: ExecutionSpec {
            runtime: RuntimeType::NativeTool,
            entrypoint: "run.sh".to_string(),
            timeout_secs: 10,
            memory_limit_mb: 256,
            allowed_interpreters: vec!["bash".to_string()],
        },
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "data": { "type": "string" } }
        }),
        policy_defaults: PolicyDefaults {
            default_tier: "tier1_human_approval".to_string(),
            max_frequency_per_trace: 5,
            default_risk_level: "high".to_string(),
            operation_kind: "write".to_string(),
        },
        egress: EgressClassification {
            contains_pii: false,
            max_payload_bytes: 65536,
            allowed_fields: vec![],
        },
    };
    static_registry
        .register_skill_direct(mutation_manifest)
        .await;

    let audit_sink = Arc::new(SqliteAuditSink::in_memory().unwrap());
    let approval_manager = Arc::new(ApprovalManager::new(Arc::new(NoopApprovalNotifier)));
    let api_key = "sk_test_admin_secret_key_888".to_string();
    let api_authenticator = Arc::new(ApiKeyAuthenticator::new(vec![api_key.clone()]));

    let engine = Arc::new(TrustEngine {
        tenancy_mode: TenancyMode::Single,
        signing_key_pair: key_pair,
        root_verifying_key: None,
        token_verifier: Some(api_authenticator),
        policy_engine,
        skill_registry: static_registry,
        nonce_store: Arc::new(InMemoryNonceStore::new()),
        taint_lineage_engine: Arc::new(BasicBinaryTaintTracker::new()),
        reputation_evaluator: Arc::new(DefaultReputationEvaluator),
        settlement_engine: Arc::new(DefaultSettlementEngine),
        dispatcher: Arc::new(LocalSubprocessDispatcher::new(native_tools_dir)),
        audit_sink,
        approval_manager,
        contract_registry: Arc::new(trust_engine::local_adapters::memory_contract::InMemoryContractRegistry::new()),
        tracked_call_chains: Arc::new(RwLock::new(HashMap::new())),
        configured_api_keys: vec![api_key.clone()],
    });

    let gateway_state = Arc::new(AppState {
        engine: engine.clone(),
        start_time: Instant::now(),
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });
    let gateway_app = build_app(gateway_state, 65536);

    let action_id = format!("act_api_{}", uuid::Uuid::new_v4());
    let action_args = serde_json::json!({ "location": "Berlin" });

    // 1. Propose action without Authorization header -> 401 UNAUTHORIZED
    let unauth_req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: action_id.clone(),
                tool_name: "claw_weather".to_string(),
                arguments: action_args.clone(),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let unauth_resp = gateway_app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Propose action with INVALID API key -> 401 UNAUTHORIZED
    let bad_key_req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_invalid_bogus_key")
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: action_id.clone(),
                tool_name: "claw_weather".to_string(),
                arguments: action_args.clone(),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let bad_key_resp = gateway_app.clone().oneshot(bad_key_req).await.unwrap();
    assert_eq!(bad_key_resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Propose standard read action with VALID API key -> 200 OK
    let good_req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: action_id.clone(),
                tool_name: "claw_weather".to_string(),
                arguments: action_args.clone(),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let good_resp = gateway_app.clone().oneshot(good_req).await.unwrap();
    assert_eq!(good_resp.status(), StatusCode::OK);

    // 4. Propose Tier 1 mutation action -> 202 ACCEPTED (pending approval)
    let mutation_action_id = format!("act_mut_{}", uuid::Uuid::new_v4());
    let mutation_args = serde_json::json!({ "data": "important update" });
    let propose_mutation_req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: mutation_action_id.clone(),
                tool_name: "claw_mutation_tool".to_string(),
                arguments: mutation_args.clone(),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let propose_mut_resp = gateway_app
        .clone()
        .oneshot(propose_mutation_req)
        .await
        .unwrap();
    assert_eq!(propose_mut_resp.status(), StatusCode::ACCEPTED);

    let body_bytes = axum::body::to_bytes(propose_mut_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let res_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(res_json["status"], "pending_approval");
    let approval_id = res_json["approval_id"].as_str().unwrap().to_string();

    // 5. Submit approval with INVALID key -> 401 UNAUTHORIZED
    let unauth_appr_req = Request::builder()
        .method("POST")
        .uri(format!("/v1/approvals/{approval_id}/decision"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_wrong_admin_key")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "approved": true,
                "resolved_by": "admin"
            }))
            .unwrap(),
        ))
        .unwrap();

    let unauth_appr_resp = gateway_app.clone().oneshot(unauth_appr_req).await.unwrap();
    assert_eq!(unauth_appr_resp.status(), StatusCode::UNAUTHORIZED);

    // 6. Submit approval with VALID admin API key -> 200 OK + ExecutionGrant released
    let good_appr_req = Request::builder()
        .method("POST")
        .uri(format!("/v1/approvals/{approval_id}/decision"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "approved": true,
                "resolved_by": "admin"
            }))
            .unwrap(),
        ))
        .unwrap();

    let good_appr_resp = gateway_app.oneshot(good_appr_req).await.unwrap();
    assert_eq!(good_appr_resp.status(), StatusCode::OK);

    let appr_body_bytes = axum::body::to_bytes(good_appr_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let appr_json: serde_json::Value = serde_json::from_slice(&appr_body_bytes).unwrap();
    assert_eq!(appr_json["status"], "approved");
    let released_grant = appr_json["grant"].as_str().unwrap();
    assert!(!released_grant.is_empty());

    // 7. Verify released grant is authentic and bound
    let pub_gateway_key = engine.signing_key_pair.public_key();
    assert!(validate_bound(
        released_grant,
        "claw_mutation_tool",
        &mutation_args,
        "executor-host",
        &pub_gateway_key
    )
    .is_ok());
}

#[tokio::test]
async fn test_conformance_scenario_5_trace_continuity_and_triage_envelope() {
    use sha2::{Digest, Sha256};
    use trust_sdk::envelope::ServiceRequestEnvelope;

    // 1. Set up mock triage agent listener on an ephemeral port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let triage_url = format!("http://127.0.0.1:{}", local_addr.port());

    let received_traceparent = Arc::new(RwLock::new(String::new()));
    let received_envelope = Arc::new(RwLock::new(Option::<ServiceRequestEnvelope>::None));
    let triage_traceparent_capture = received_traceparent.clone();
    let triage_envelope_capture = received_envelope.clone();
    let expected_aud = triage_url.clone();

    tokio::spawn(async move {
        let triage_app = axum::Router::new().route(
            "/v1/triage/evaluate",
            axum::routing::post({
                let aud = expected_aud.clone();
                move |headers: axum::http::HeaderMap, body_bytes: axum::body::Bytes| {
                    let aud = aud.clone();
                    let tp = triage_traceparent_capture.clone();
                    let tc = triage_envelope_capture.clone();
                    async move {
                        let tp_header = headers
                            .get("traceparent")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let env_header = headers
                            .get("x-service-envelope")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or_default()
                            .to_string();

                        let envelope: ServiceRequestEnvelope =
                            serde_json::from_str(&env_header).expect("Envelope deserialization");

                        // Check audience
                        assert_eq!(envelope.audience, aud);

                        // Check body hash
                        let mut hasher = Sha256::new();
                        hasher.update(&body_bytes);
                        let computed_hash = format!("{:x}", hasher.finalize());
                        assert_eq!(envelope.body_sha256, computed_hash);

                        // Verify Ed25519 signature from did:twin
                        let pubkey_bytes =
                            trust_sdk::did::extract_did_twin_ed25519_pubkey(&envelope.caller_did)
                                .expect("Extract did:twin key");
                        let verifying_key =
                            ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
                                .expect("VerifyingKey");
                        envelope
                            .verify_signature(&verifying_key)
                            .expect("Signature verification");

                        *tp.write().await = tp_header;
                        *tc.write().await = Some(envelope);

                        axum::Json(serde_json::json!({
                            "recommendation": "recommend_reject",
                            "dossier": {
                                "mitigation_notes": "Novel unapproved action denied by cognitive triage."
                            }
                        }))
                    }
                }
            }),
        );
        let _ = axum::serve(listener, triage_app).await;
    });

    // 2. Configure Trust Engine with triage_agent_url
    let key_pair = Ed25519KeyPair::generate();
    let policy_toml = format!(
        r#"
[governance]
policy_version = "1.0.0"
default_action = "deny"
input_hash_binding_required = true
max_grant_ttl_seconds = 30
triage_agent_url = "{}"

[[rules]]
name = "Auto-allow read-only operations"
operation_kind = "read"
action = "allow"
priority = 10
"#,
        triage_url
    );

    let policy_engine = Arc::new(PolicyEngine::from_toml(&policy_toml).unwrap());
    let native_tools_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../native_tools");
    let static_registry = Arc::new(StaticSkillRegistry::new(native_tools_dir, false));
    static_registry.load_all().await.unwrap();

    // Register a novel unmatched skill
    let novel_manifest = SkillManifest {
        schema_version: "lianxi.skill/v1".to_string(),
        id: "io.lianxi.skill.novel_tool@v1".to_string(),
        name: "claw_novel_tool".to_string(),
        version: "1.0.0".to_string(),
        description: "An unclassified novel tool".to_string(),
        author_did: "did:web:lianxi.io".to_string(),
        data_origin_trust: DataOriginTrust::TrustedInternal,
        lineage_rules: vec![],
        execution: ExecutionSpec {
            runtime: RuntimeType::NativeTool,
            entrypoint: "run.sh".to_string(),
            timeout_secs: 10,
            memory_limit_mb: 256,
            allowed_interpreters: vec!["bash".to_string()],
        },
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "cmd": { "type": "string" } }
        }),
        policy_defaults: PolicyDefaults {
            default_tier: "tier1_require_human_approval".to_string(),
            max_frequency_per_trace: 5,
            default_risk_level: "high".to_string(),
            operation_kind: "unmatched_novel_kind".to_string(),
        },
        egress: EgressClassification {
            contains_pii: false,
            max_payload_bytes: 65536,
            allowed_fields: vec![],
        },
    };
    static_registry.register_skill_direct(novel_manifest).await;

    let audit_sink = Arc::new(SqliteAuditSink::in_memory().unwrap());
    let approval_manager = Arc::new(ApprovalManager::new(Arc::new(NoopApprovalNotifier)));
    let nonce_store = Arc::new(InMemoryNonceStore::new());
    let taint_lineage_engine = Arc::new(BasicBinaryTaintTracker::new());
    let reputation_evaluator = Arc::new(DefaultReputationEvaluator);
    let settlement_engine = Arc::new(DefaultSettlementEngine);
    let dispatcher = Arc::new(LocalSubprocessDispatcher::new(native_tools_dir));

    let engine = Arc::new(TrustEngine {
        tenancy_mode: TenancyMode::Single,
        signing_key_pair: key_pair,
        root_verifying_key: None,
        token_verifier: None,
        policy_engine,
        skill_registry: static_registry,
        nonce_store,
        taint_lineage_engine,
        reputation_evaluator,
        settlement_engine,
        dispatcher,
        audit_sink: audit_sink.clone(),
        approval_manager,
        contract_registry: Arc::new(trust_engine::local_adapters::memory_contract::InMemoryContractRegistry::new()),
        tracked_call_chains: Arc::new(RwLock::new(HashMap::new())),
        configured_api_keys: vec!["sk_test_trace_key".to_string()],
    });

    let state = Arc::new(AppState {
        engine: engine.clone(),
        start_time: Instant::now(),
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });

    let gateway_app = build_app(state, 65536);

    // 3. Propose action on the unmatched tool
    let test_trace_id = "trace_mesh_continuity_42";
    let propose_req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_test_trace_key")
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: "act_continuity_99".to_string(),
                tool_name: "claw_novel_tool".to_string(),
                arguments: serde_json::json!({ "cmd": "eval" }),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                call_chain: Some(trust_sdk::model::CallChainContext::new(test_trace_id)),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let resp = gateway_app.oneshot(propose_req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    // Triage returned recommend_reject -> Gateway must reject with BAD_REQUEST containing the mitigation note
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body_str.contains("Novel unapproved action denied by cognitive triage."));

    // 4. Verify Triage received envelope with traceparent
    let captured_tp = received_traceparent.read().await.clone();
    assert!(captured_tp.contains(test_trace_id), "traceparent header should contain trace_id: {captured_tp}");
    let captured_env = received_envelope.read().await.clone();
    assert!(captured_env.is_some(), "Triage received verified envelope");
    let env = captured_env.unwrap();
    assert_eq!(env.path, "/v1/triage/evaluate");

    // 5. Query Audit Sink for trace_id
    let audit_events = audit_sink.get_events_by_trace(test_trace_id).unwrap();
    assert!(!audit_events.is_empty(), "Audit events must be recorded for trace_id");
    for event in &audit_events {
        assert_eq!(event.trace_id, test_trace_id);
    }
}

#[tokio::test]
async fn test_conformance_scenario_7_contract_validation_and_grant_binding() {
    let (engine, _audit_sink) = setup_test_engine().await;

    // Register a signed contract for claw_weather
    let seed = [99u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut contract = trust_sdk::contracts::SignedContract {
        contract_id: "contract_weather_v1".to_string(),
        version: "1.0.0".to_string(),
        skill_id: "claw_weather".to_string(),
        author_did: "did:web:weather.org".to_string(),
        schema_hash: "hash_schema_xyz".to_string(),
        input_constraints: Some(trust_sdk::contracts::InputConstraints {
            max_amount_cents: Some(5000),
            required_fields: Some(vec!["location".to_string()]),
            forbidden_fields: None,
            allowed_operations: None,
        }),
        mapping_ir_hash: None,
        created_at: 1730000000,
        expires_at: 1799999999,
        signature: String::new(),
    };
    contract.sign(&signing_key).unwrap();
    engine.contract_registry.register_contract(contract).await.unwrap();

    let state = Arc::new(AppState {
        engine: engine.clone(),
        start_time: Instant::now(),
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });
    let app = build_app(state, 65536);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_test_dev_key")
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: "act_contract_valid_1".to_string(),
                tool_name: "claw_weather".to_string(),
                arguments: serde_json::json!({ "location": "Tokyo" }),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_conformance_scenario_8_contract_violation_and_drift_audit() {
    let (engine, audit_sink) = setup_test_engine().await;

    // Register contract requiring max $50.00 (5000 cents)
    let seed = [99u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut contract = trust_sdk::contracts::SignedContract {
        contract_id: "contract_weather_v2".to_string(),
        version: "1.0.0".to_string(),
        skill_id: "claw_weather".to_string(),
        author_did: "did:web:weather.org".to_string(),
        schema_hash: "hash_schema_xyz".to_string(),
        input_constraints: Some(trust_sdk::contracts::InputConstraints {
            max_amount_cents: Some(5000),
            required_fields: Some(vec!["location".to_string()]),
            forbidden_fields: None,
            allowed_operations: None,
        }),
        mapping_ir_hash: None,
        created_at: 1730000000,
        expires_at: 1799999999,
        signature: String::new(),
    };
    contract.sign(&signing_key).unwrap();
    engine.contract_registry.register_contract(contract).await.unwrap();

    let state = Arc::new(AppState {
        engine: engine.clone(),
        start_time: Instant::now(),
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });
    let app = build_app(state, 65536);

    let drift_trace_id = "trace_drift_detector_99";
    // Submit with amount exceeding limit -> 10000 cents
    let req = Request::builder()
        .method("POST")
        .uri("/v1/actions/propose")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer sk_test_dev_key")
        .header("x-trace-id", drift_trace_id)
        .body(Body::from(
            serde_json::to_string(&ProposedAction {
                action_id: "act_contract_drift_1".to_string(),
                tool_name: "claw_weather".to_string(),
                arguments: serde_json::json!({ "location": "Tokyo", "amount_cents": 10000 }),
                tenant_id: "default".to_string(),
                workspace_id: "default".to_string(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("Contract violation"));

    // Check drift audit event in SQLite audit trail
    let events = audit_sink.get_events_by_trace(drift_trace_id).unwrap();
    assert!(events.iter().any(|e| e.event_type == "contract_drift"));
}

#[tokio::test]
async fn test_conformance_scenario_9_contract_registration_and_retrieval_api() {
    let (engine, _) = setup_test_engine().await;

    let state = Arc::new(AppState {
        engine: engine.clone(),
        start_time: Instant::now(),
        sse_sessions: Arc::new(RwLock::new(HashMap::new())),
    });
    let app = build_app(state, 65536);

    let seed = [88u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut contract = trust_sdk::contracts::SignedContract {
        contract_id: "contract_api_endpoint_test".to_string(),
        version: "1.0.0".to_string(),
        skill_id: "claw_weather".to_string(),
        author_did: "did:web:partner.com".to_string(),
        schema_hash: "hash_999".to_string(),
        input_constraints: None,
        mapping_ir_hash: None,
        created_at: 1730000000,
        expires_at: 1799999999,
        signature: String::new(),
    };
    contract.sign(&signing_key).unwrap();

    // 1. POST /v1/contracts
    let post_req = Request::builder()
        .method("POST")
        .uri("/v1/contracts")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&contract).unwrap()))
        .unwrap();

    let post_resp = app.clone().oneshot(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::CREATED);

    // 2. GET /v1/contracts/:id
    let get_req = Request::builder()
        .method("GET")
        .uri("/v1/contracts/contract_api_endpoint_test")
        .body(Body::empty())
        .unwrap();

    let get_resp = app.oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
    let retrieved: trust_sdk::contracts::SignedContract = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(retrieved.contract_id, "contract_api_endpoint_test");
    assert_eq!(retrieved.signature, contract.signature);
}
