use gateway::contract_verifier::{ContractVerifier, DefaultContractVerifier};
use std::sync::Arc;
use trust_contract::{
    ContractCapability, ContractConstraints, ContractMoney, ContractStore, ContractValidity,
    DataPolicy, InMemoryContractStore, InteractionContract, PartyIdentity, ProtocolBinding,
    Purpose,
};
use trust_core::action::{ActionDescriptor, ActionRequest, OperationKind};
use trust_core::actor::{ActorContext, AuthLevel, SourceContext};
use trust_core::grant::GrantClearance;

fn create_sample_active_contract(
    contract_id: &str,
    expires_in_secs: i64,
) -> (InteractionContract, String) {
    let now = chrono::Utc::now();
    let contract = InteractionContract {
        contract_id: contract_id.to_string(),
        version: 1,
        state: trust_contract::ContractState::Active,
        issuer: PartyIdentity::new_did("did:web:company-a.com"),
        counterparty: PartyIdentity::new_did("did:twin:company-b.com"),
        purpose: Purpose {
            code: "procurement".to_string(),
            description: "B2B Procurement".to_string(),
        },
        capabilities: vec![ContractCapability {
            capability_id: "io.company.orders@v1".to_string(),
            operations: vec!["create".to_string(), "status".to_string()],
            parameter_constraints: None,
            result_constraints: None,
        }],
        constraints: ContractConstraints {
            max_transaction_value: Some(ContractMoney {
                amount_minor: 2500000, // €25,000.00
                currency: "EUR".to_string(),
            }),
            allowed_geographies: vec!["EU".to_string(), "FR".to_string(), "DE".to_string()],
            max_units: Some(1000),
            cancellation_terms: Some("before_dispatch".to_string()),
            custom_constraints: std::collections::BTreeMap::new(),
        },
        data_policy: DataPolicy::default(),
        obligations: vec![],
        commercial_terms: None,
        validity: ContractValidity {
            valid_from: now - chrono::Duration::hours(1),
            valid_until: now + chrono::Duration::seconds(expires_in_secs),
        },
        protocol: ProtocolBinding::default(),
        evidence: Default::default(),
        parent_contract_id: None,
        previous_contract_hash: None,
        created_at: now,
        updated_at: now,
    };
    let hash = trust_contract::compute_contract_hash(&contract).unwrap();
    (contract, hash)
}

#[tokio::test]
async fn test_valid_contract_verification_and_grant_issuance() {
    let store = Arc::new(InMemoryContractStore::new());
    let (contract, hash) = create_sample_active_contract("ctr_valid_01", 3600);
    store.put_contract("tenant_alpha", contract).await.unwrap();

    let verifier = DefaultContractVerifier::new(store);

    let contract_ctx = serde_json::json!({
        "contract_id": "ctr_valid_01",
        "contract_hash": hash,
        "capability_id": "io.company.orders@v1",
    });

    let args = serde_json::json!({
        "sku": "ABC-123",
        "quantity": 500,
        "amount": {
            "amount_minor": 1500000,
            "currency": "EUR"
        },
        "country": "FR"
    });

    let result = verifier
        .verify_action(
            "tenant_alpha",
            "did:web:company-a.com",
            "io.company.orders.create",
            &args,
            &contract_ctx,
        )
        .await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.contract_id, "ctr_valid_01");
    assert_eq!(verified.contract_hash, hash);

    // Verify Grant issuance binds contract_id and contract_hash
    let issuer = gateway::grant::Ed25519GrantIssuer::generate("kid_test".to_string());
    let req = ActionRequest {
        action_id: "act_001".to_string(),
        tenant_id: "tenant_alpha".to_string(),
        workspace_id: "default".to_string(),
        actor: ActorContext {
            owner_did: "did:web:company-a.com".to_string(),
            requester_did: "did:web:company-a.com".to_string(),
            user_did: None,
            session_jti: "sess_001".to_string(),
            auth_level: AuthLevel::Level4Verified,
            auth_method: Default::default(),
            oauth_scopes: vec![],
        },
        source: SourceContext::ssi_agent(),
        action: ActionDescriptor {
            name: "io.company.orders.create".to_string(),
            category: "orders".to_string(),
            resource: None,
            operation: OperationKind::Create,
            amount: None,
            arguments: args,
            tags: vec![],
            contract_context: Some(contract_ctx),
        },
        contract_context: None,
        call_chain_context: None,
    };

    let signed_grant = issuer
        .issue(
            &req,
            GrantClearance::AutoApproved,
            std::time::Duration::from_secs(30),
        )
        .unwrap();

    assert_eq!(
        signed_grant.claims.contract_id,
        Some("ctr_valid_01".to_string())
    );
    assert_eq!(signed_grant.claims.contract_hash, Some(hash));
}

#[tokio::test]
async fn test_expired_contract_rejected() {
    let store = Arc::new(InMemoryContractStore::new());
    let (contract, hash) = create_sample_active_contract("ctr_expired_01", -3600); // Expired 1 hr ago
    store.put_contract("tenant_alpha", contract).await.unwrap();

    let verifier = DefaultContractVerifier::new(store);
    let contract_ctx = serde_json::json!({
        "contract_id": "ctr_expired_01",
        "contract_hash": hash,
        "capability_id": "io.company.orders@v1",
    });

    let args = serde_json::json!({"quantity": 10});
    let result = verifier
        .verify_action(
            "tenant_alpha",
            "did:web:company-a.com",
            "io.company.orders.create",
            &args,
            &contract_ctx,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        trust_contract::ContractError::ContractExpired(..)
    ));
}

#[tokio::test]
async fn test_tampered_contract_hash_rejected() {
    let store = Arc::new(InMemoryContractStore::new());
    let (contract, _hash) = create_sample_active_contract("ctr_tamper_01", 3600);
    store.put_contract("tenant_alpha", contract).await.unwrap();

    let verifier = DefaultContractVerifier::new(store);
    let fake_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let contract_ctx = serde_json::json!({
        "contract_id": "ctr_tamper_01",
        "contract_hash": fake_hash,
        "capability_id": "io.company.orders@v1",
    });

    let args = serde_json::json!({"quantity": 10});
    let result = verifier
        .verify_action(
            "tenant_alpha",
            "did:web:company-a.com",
            "io.company.orders.create",
            &args,
            &contract_ctx,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        trust_contract::ContractError::ContractHashMismatch { .. }
    ));
}

#[tokio::test]
async fn test_amount_exceeded_rejected() {
    let store = Arc::new(InMemoryContractStore::new());
    let (contract, hash) = create_sample_active_contract("ctr_limit_01", 3600);
    store.put_contract("tenant_alpha", contract).await.unwrap();

    let verifier = DefaultContractVerifier::new(store);
    let contract_ctx = serde_json::json!({
        "contract_id": "ctr_limit_01",
        "contract_hash": hash,
        "capability_id": "io.company.orders@v1",
    });

    // Limit is €25,000 (2,500,000 minor units). Request €30,000 (3,000,000 minor units).
    let args = serde_json::json!({
        "amount": {
            "amount_minor": 3000000,
            "currency": "EUR"
        }
    });

    let result = verifier
        .verify_action(
            "tenant_alpha",
            "did:web:company-a.com",
            "io.company.orders.create",
            &args,
            &contract_ctx,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        trust_contract::ContractError::ArgumentConstraintViolation { .. }
    ));
}

#[tokio::test]
async fn test_unauthorized_party_rejected() {
    let store = Arc::new(InMemoryContractStore::new());
    let (contract, hash) = create_sample_active_contract("ctr_party_01", 3600);
    store.put_contract("tenant_alpha", contract).await.unwrap();

    let verifier = DefaultContractVerifier::new(store);
    let contract_ctx = serde_json::json!({
        "contract_id": "ctr_party_01",
        "contract_hash": hash,
        "capability_id": "io.company.orders@v1",
    });

    let args = serde_json::json!({});
    let result = verifier
        .verify_action(
            "tenant_alpha",
            "did:web:impostor.com",
            "io.company.orders.create",
            &args,
            &contract_ctx,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        trust_contract::ContractError::CounterpartyMismatch { .. }
    ));
}
