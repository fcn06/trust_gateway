use trust_verifier::{verify_input_binding, ExecutionGrant, GrantClearance, VerifierError};

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
        ..Default::default()
    };


    let args = serde_json::json!({"summary": "meeting"});
    // Attempting to execute unauthorized tool 'stripe.refund' with calendar grant must be REJECTED!
    let result = verify_input_binding(&grant, "stripe.refund", &args);
    assert!(result.is_err(), "Grant re-targeting to unauthorized tool must fail!");
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
