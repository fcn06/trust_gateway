use gateway::grant::Ed25519GrantIssuer;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use trust_core::action::{ActionDescriptor, ActionRequest, OperationKind};
use trust_core::actor::{ActorContext, AuthLevel, SourceContext};
use trust_core::errors::NonceError;
use trust_core::grant::GrantClearance;
use trust_core::grant_validator::GrantValidator;
use trust_core::traits::NonceStore;
use trust_policy::rules::{PolicyMatcher, PolicyRule};
use trust_verifier::{verify_input_binding, ExecutionGrant, VerifierError};

#[derive(Default)]
struct InMemoryNonceStore {
    seen: Mutex<HashSet<String>>,
}

#[async_trait::async_trait]
impl NonceStore for InMemoryNonceStore {
    async fn consume(&self, jti: &str, _ttl: std::time::Duration) -> Result<(), NonceError> {
        let mut lock = self.seen.lock().await;
        if lock.contains(jti) {
            return Err(NonceError::AlreadyConsumed {
                jti: jti.to_string(),
            });
        }
        lock.insert(jti.to_string());
        Ok(())
    }
}

fn create_sample_action_request(action_name: &str, args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        action_id: format!("act_{}", uuid::Uuid::new_v4()),
        tenant_id: "box_demo_shop".to_string(),
        workspace_id: "default".to_string(),
        actor: ActorContext {
            owner_did: "did:twin:user".to_string(),
            requester_did: "did:twin:agent".to_string(),
            user_did: None,
            session_jti: "sess_001".to_string(),
            auth_level: AuthLevel::Level3Session,
            auth_method: Default::default(),
            oauth_scopes: vec![],
        },
        source: SourceContext::ssi_agent(),
        action: ActionDescriptor {
            name: action_name.to_string(),
            category: "checkout".to_string(),
            resource: None,
            operation: OperationKind::Create,
            amount: None,
            arguments: args,
            tags: vec![],
            contract_context: None,
        },
        contract_context: None,
        call_chain_context: None,
    }
}

#[test]
fn test_negative_invariant_invalid_action_rejected() {
    let grant = ExecutionGrant {
        grant_id: "inv_001".to_string(),
        action_id: "act_001".to_string(),
        tenant_id: "tenant_alpha".to_string(),
        workspace_id: "default".to_string(),
        owner_did: "did:twin:user".to_string(),
        requester_did: "did:twin:agent".to_string(),
        executor_id: "exec_1".to_string(),
        allowed_action: "google.calendar.event.create".to_string(),
        tool_version: "1.0.0".to_string(),
        clearance: GrantClearance::AutoApproved,
        expires_at: chrono::Utc::now().timestamp() + 300,
        kid: None,
        input_hash: trust_verifier::canonical_hash(&serde_json::json!({"summary": "meeting"})),
        policy_hash: String::new(),
        registry_hash: String::new(),
        delegation: None,
        budget: None,
        contract_id: None,
        contract_hash: None,
        ..Default::default()
    };

    let args = serde_json::json!({"summary": "meeting"});
    // Attempting to execute unauthorized tool 'stripe.refund' with calendar grant must be REJECTED!
    let result = verify_input_binding(&grant, "stripe.refund", &args);
    assert!(
        result.is_err(),
        "Grant re-targeting to unauthorized tool must fail!"
    );
    if let Err(VerifierError::ActionMismatch { allowed, requested }) = result {
        assert_eq!(allowed, "google.calendar.event.create");
        assert_eq!(requested, "stripe.refund");
    } else {
        panic!("Expected ActionMismatch error variant");
    }
}

#[test]
fn test_negative_invariant_tampered_input_rejected() {
    let grant = ExecutionGrant {
        grant_id: "inv_002".to_string(),
        allowed_action: "stripe.refund".to_string(),
        input_hash: trust_verifier::canonical_hash(&serde_json::json!({"amount": 100})),
        expires_at: chrono::Utc::now().timestamp() + 300,
        ..Default::default()
    };

    // Tampered payload trying to refund $10,000 instead of $100
    let tampered_args = serde_json::json!({"amount": 10000});
    let result = verify_input_binding(&grant, "stripe.refund", &tampered_args);
    assert!(result.is_err(), "Tampered arguments must be REJECTED!");
    if let Err(VerifierError::InputHashMismatch { .. }) = result {
        // Expected
    } else {
        panic!("Expected InputHashMismatch error variant");
    }
}

#[tokio::test]
async fn test_negative_invariant_expired_grant_rejected() {
    let issuer = Ed25519GrantIssuer::generate("key-test-expired".to_string());
    let validator = GrantValidator::from_ed25519_pem(&issuer.public_key_pem()).unwrap();

    let req =
        create_sample_action_request("box_shop_checkout", serde_json::json!({"amount": 42.50}));
    // Issue grant with 0s TTL (expires immediately)
    let signed = issuer
        .issue(
            &req,
            GrantClearance::HumanApproved,
            std::time::Duration::from_secs(0),
        )
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let res = validator.validate(&signed.token).await;
    assert!(res.is_err(), "Expired grant must be REJECTED!");
    let err_str = res.err().unwrap().to_string();
    assert!(
        err_str.contains("expired"),
        "Error should indicate expiry, got: {err_str}"
    );
}

#[tokio::test]
async fn test_negative_invariant_replayed_grant_rejected() {
    let issuer = Ed25519GrantIssuer::generate("key-test-replay".to_string());
    let nonce_store = Arc::new(InMemoryNonceStore::default());
    let validator = GrantValidator::from_ed25519_pem(&issuer.public_key_pem())
        .unwrap()
        .with_nonce_store(nonce_store);

    let req =
        create_sample_action_request("box_shop_checkout", serde_json::json!({"amount": 10.00}));
    let signed = issuer
        .issue(
            &req,
            GrantClearance::HumanApproved,
            std::time::Duration::from_secs(30),
        )
        .unwrap();

    // First presentation: must succeed
    let first = validator.validate(&signed.token).await;
    assert!(first.is_ok(), "First grant presentation must be accepted");

    // Second presentation: replay attack must fail!
    let second = validator.validate(&signed.token).await;
    assert!(
        second.is_err(),
        "Replayed grant presentation must be REJECTED!"
    );
    let err_str = second.err().unwrap().to_string();
    assert!(
        err_str.contains("replay"),
        "Error should indicate replay, got: {err_str}"
    );
}

#[test]
fn test_negative_invariant_guest_mutation_denied() {
    let rule = PolicyRule {
        id: "guest-mutations-deny".to_string(),
        priority: 9,
        matcher: PolicyMatcher {
            operation_kinds: Some(vec![
                "create".to_string(),
                "update".to_string(),
                "delete".to_string(),
                "financial_mutation".to_string(),
            ]),
            session_tier: Some("guest".to_string()),
            ..Default::default()
        },
        effect: "deny".to_string(),
        tier: None,
        proof_type: None,
        required_claims: vec![],
        reason: Some(
            "Personal agent in guest session cannot execute mutations. Customer account sign-in required.".to_string(),
        ),
    };

    let mut req =
        create_sample_action_request("box_shop_checkout", serde_json::json!({"amount": 25.0}));
    req.actor.auth_level = AuthLevel::Level0Guest;

    assert!(
        rule.matcher.matches(&req),
        "Guest mutation must match guest-mutations-deny rule"
    );
    assert_eq!(rule.effect, "deny");
    assert_eq!(
        rule.reason.as_deref(),
        Some("Personal agent in guest session cannot execute mutations. Customer account sign-in required.")
    );
}
