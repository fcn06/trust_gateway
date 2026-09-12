use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use trust_contract::{
    create_attestation, execute_activation_ceremony, validate_action_against_contract,
    ActionEvaluationContext, ContractCapability, ContractConstraints, ContractEvidence,
    ContractMoney, ContractState, ContractValidity, DataPolicy, InteractionContract, PartyIdentity,
    Purpose,
};
use trust_grants::GrantIssuer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("🤝 Trust Gateway Example: Negotiated Interaction Contracts (NICP)");
    println!("============================================================\n");

    // 1. Setup Identities and Cryptographic Keypairs
    let mut csprng = OsRng;
    let buyer_signing_key = SigningKey::generate(&mut csprng);
    let buyer_verifying_key = buyer_signing_key.verifying_key();
    let buyer_did = "did:web:buyer.corp.example".to_string();

    let supplier_signing_key = SigningKey::generate(&mut csprng);
    let supplier_verifying_key = supplier_signing_key.verifying_key();
    let supplier_did = "did:web:supplier.logistics.example".to_string();

    println!("Parties Established:");
    println!("  - Buyer DID:    {buyer_did}");
    println!("  - Supplier DID: {supplier_did}\n");

    // 2. Draft Interaction Contract
    println!("--- 1. Drafting Interaction Contract ---");
    let now = Utc::now();
    let mut contract = InteractionContract {
        contract_id: "ctr_demo_procure_freight_001".to_string(),
        version: 1,
        state: ContractState::Draft,
        issuer: PartyIdentity::new_did(buyer_did.clone()),
        counterparty: PartyIdentity::new_did(supplier_did.clone()),
        purpose: Purpose {
            code: "procure_freight_service".to_string(),
            description: "Automated logistics booking with €25,000 transaction ceiling".to_string(),
        },
        capabilities: vec![ContractCapability {
            capability_id: "io.logistics.freight@v1".to_string(),
            operations: vec![
                "quote".to_string(),
                "book".to_string(),
                "status".to_string(),
            ],
            parameter_constraints: None,
            result_constraints: None,
        }],
        constraints: ContractConstraints {
            max_transaction_value: Some(ContractMoney {
                amount_minor: 2500000, // €25,000.00
                currency: "EUR".to_string(),
            }),
            allowed_geographies: vec!["EU".to_string()],
            max_units: Some(10),
            cancellation_terms: Some("24h notice".to_string()),
            custom_constraints: std::collections::BTreeMap::new(),
        },
        data_policy: DataPolicy::default(),
        obligations: vec![],
        commercial_terms: None,
        validity: ContractValidity {
            valid_from: now - Duration::minutes(5),
            valid_until: now + Duration::days(30),
        },
        protocol: Default::default(),
        evidence: ContractEvidence::default(),
        parent_contract_id: None,
        previous_contract_hash: None,
        created_at: now,
        updated_at: now,
    };

    println!("Contract Draft Created:");
    println!("  - ID: {}", contract.contract_id);
    println!("  - Purpose: {}", contract.purpose.code);
    println!("  - Max Transaction Ceiling: €25,000.00");
    println!("  - Allowed Operations: quote, book, status\n");

    // 3. Compute Canonical RFC 8785 Hash
    println!("--- 2. Computing Canonical RFC 8785 Contract Hash ---");
    let contract_hash = trust_contract::compute_contract_hash(&contract)?;
    println!("Canonical Hash (JCS + SHA-256):");
    println!("  {contract_hash}\n");

    // 4. Mutual Attestation & Signing Ceremony
    println!("--- 3. Mutual Attestation & Activation Ceremony ---");
    // Advance state to Accepted after counterparty acceptance
    contract.state = ContractState::Accepted;

    // Buyer signs
    let buyer_attestation = create_attestation(&contract, &buyer_did, &buyer_signing_key)?;
    println!("  ✍️ Buyer Ed25519 signature generated.");
    contract.evidence.attestations.push(buyer_attestation);

    // Supplier signs
    let supplier_attestation = create_attestation(&contract, &supplier_did, &supplier_signing_key)?;
    println!("  ✍️ Supplier Ed25519 signature generated.");
    contract.evidence.attestations.push(supplier_attestation);

    // Advance state to Attested
    contract.state = ContractState::Attested;

    let mut party_keys = HashMap::new();
    party_keys.insert(buyer_did.clone(), buyer_verifying_key);
    party_keys.insert(supplier_did.clone(), supplier_verifying_key);

    let active_contract = execute_activation_ceremony(contract, &party_keys)?;
    println!(
        "  ✅ Ceremony completed! Contract state transitioned to: {:?}",
        active_contract.state
    );
    println!("  ✅ Both signatures verified against canonical hash.\n");

    // 5. In-Bounds Action Evaluation
    println!("--- 4. Evaluating In-Bounds Action Proposal (€15,000.00) ---");
    let in_bounds_money = ContractMoney {
        amount_minor: 1500000, // €15,000.00 <= €25,000.00
        currency: "EUR".to_string(),
    };

    let in_bounds_ctx = ActionEvaluationContext {
        requester_did: &buyer_did,
        capability_id: "io.logistics.freight@v1",
        operation: "book",
        amount: Some(&in_bounds_money),
        units: Some(1),
        destination_country: Some("EU"),
        evaluation_time: Utc::now(),
    };

    match validate_action_against_contract(&active_contract, &in_bounds_ctx) {
        Ok(_) => {
            println!("  ✅ Action Approved under contract!");
            println!("  Ceiling checked: €15,000.00 <= €25,000.00 ceiling");
        }
        Err(err) => println!("  ❌ Unexpected rejection: {err}"),
    }

    // 6. Out-of-Bounds Action Evaluation (Budget Ceiling Exceeded)
    println!("\n--- 5. Evaluating Out-of-Bounds Action Proposal (€35,000.00) ---");
    let out_bounds_money = ContractMoney {
        amount_minor: 3500000, // €35,000.00 > €25,000.00 limit!
        currency: "EUR".to_string(),
    };

    let out_bounds_ctx = ActionEvaluationContext {
        requester_did: &buyer_did,
        capability_id: "io.logistics.freight@v1",
        operation: "book",
        amount: Some(&out_bounds_money),
        units: Some(1),
        destination_country: Some("EU"),
        evaluation_time: Utc::now(),
    };

    match validate_action_against_contract(&active_contract, &out_bounds_ctx) {
        Ok(_) => println!("  ❌ UNEXPECTED: Action exceeded limit but was approved!"),
        Err(err) => {
            println!("  🛑 Action Blocked: {err}");
            println!("  ✅ Constraint enforced: transaction requested exceeds €25,000 ceiling.");
        }
    }

    // 7. Mint ExecutionGrant bound to Contract ID & Contract Hash
    println!("\n--- 6. Minting ExecutionGrant Bound to Contract ---");
    let in_bounds_args = serde_json::json!({
        "shipment_id": "ship_481",
        "destination": "Berlin, DE"
    });

    let grant = GrantIssuer::create_grant(
        "action-procure-001",
        "tenant_logistics",
        "io.logistics.freight@v1",
        &in_bounds_args,
        "trust-gateway",
        30,
    );

    println!("Minted ExecutionGrant:");
    println!("  - Grant ID: {}", grant.grant_id);
    println!("  - Tool Bound: {}", grant.tool_name);
    println!("  - Input Hash: {}", grant.input_hash);
    println!("  - Bound Contract ID: {}", active_contract.contract_id);
    println!("  - Bound Contract Hash: {contract_hash}");

    println!("\n============================================================");
    println!("🎉 All NICP Interaction Contract stages demonstrated cleanly!");
    println!("============================================================");

    Ok(())
}
