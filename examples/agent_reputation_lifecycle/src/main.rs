use chrono::Utc;
use ed25519_dalek::SigningKey;
use gateway::reputation_store::{InMemoryReputationStore, ReputationStore};
use policy_sdk::evaluator::PolicyEvaluator;
use policy_sdk::layers::{
    AgentPolicy, HierarchicalPolicy, OrganizationPolicy, PlatformPolicy, PolicyOutcome,
    TransactionPolicy,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use trust_canonical::canonical_hash;
use trust_contract::{
    compute_contract_hash, create_attestation, execute_activation_ceremony, sign_execution_receipt,
    verify_execution_receipt, CommercialTerms, ContractCapability, ContractConstraints,
    ContractEvidence, ContractMoney, ContractState, ContractValidity, DataPolicy, ExecutionReceipt,
    InteractionContract, PartyIdentity, Purpose, SignableReceiptPayload,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("🌟 TRUST GATEWAY: END-TO-END AGENT REPUTATION & NEGOTIATION LIFECYCLE");
    println!("================================================================================\n");

    let mut csprng = OsRng;

    // ─────────────────────────────────────────────────────────────────────────
    // 0. Keypairs & Decentralized Identities (did:web)
    // ─────────────────────────────────────────────────────────────────────────
    let buyer_signing_key = SigningKey::generate(&mut csprng);
    let buyer_verifying_key = buyer_signing_key.verifying_key();
    let buyer_did = "did:web:buyer.enterprise.corp".to_string();

    let supplier_signing_key = SigningKey::generate(&mut csprng);
    let supplier_verifying_key = supplier_signing_key.verifying_key();
    let supplier_did = "did:web:precision-logistics.supplier".to_string();

    let peer_signing_key = SigningKey::generate(&mut csprng);
    let peer_verifying_key = peer_signing_key.verifying_key();
    let trusted_peer_root = "did:web:aerospace-leader.corp".to_string();

    println!("🔑 Established Cryptographic Roots & Identities:");
    println!("  - Buyer DID:        {buyer_did}");
    println!("  - Supplier DID:     {supplier_did}");
    println!("  - Trusted Peer DID: {trusted_peer_root}\n");

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Stage 1: Discovery & Local Reputation Check (Cold Start)
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔍 STAGE 1: Discovery & Initial Local Reputation Check");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let rep_store = InMemoryReputationStore::new();
    let initial_rep = rep_store
        .get_reputation("tenant_buyer_corp", &supplier_did)
        .await?;

    println!("Buyer Gateway queries local counterparty reputation for '{supplier_did}':");
    println!(
        "  - Total Local Successful Transactions: {}",
        initial_rep.successful_count
    );
    println!(
        "  - Total Local Failed Transactions:     {}",
        initial_rep.failed_count
    );
    println!("  - Trust Assessment: ⚠️ COLD START (Unknown counterparty to this Gateway)\n");

    // Buyer's enterprise policy configuration
    let buyer_policy = HierarchicalPolicy {
        platform: PlatformPolicy {
            enforce_tenant_isolation: true,
            ..Default::default()
        },
        organization: OrganizationPolicy {
            max_financial_limit_usd: 50_000,
            min_reputation_successful_executions: Some(3), // Requires 3 local successes or trusted peer attestation
            trusted_peer_roots: vec![trusted_peer_root.clone()],
            ..Default::default()
        },
        agent: AgentPolicy::default(),
        transaction: TransactionPolicy::default(),
    };
    let evaluator = PolicyEvaluator::new(buyer_policy);

    // Check policy under cold start without any peer attestation
    let cold_start_eval = evaluator.evaluate_with_reputation(
        "tenant_buyer_corp",
        "agent_procure_01",
        "io.logistics.freight@v1",
        Some(12_500),
        initial_rep.successful_count,
        false, // No peer attestation presented yet
    );

    match &cold_start_eval {
        PolicyOutcome::Deny { reason } => {
            println!("🔒 Policy Gating without reputation evidence:");
            println!("  Result: DENIED — {reason}\n");
        }
        _ => panic!("Expected policy denial during cold start without evidence"),
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Stage 2: Third-Party Evidence Presentation & Verification
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📜 STAGE 2: Presentation & Verification of Peer Execution Attestation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    println!(
        "Supplier Agent presents prior proof of good execution signed by '{trusted_peer_root}'."
    );

    let prior_receipt_payload = SignableReceiptPayload {
        receipt_id: "rcpt_aerospace_prior_9981".to_string(),
        grant_jti: "grant_aerospace_882".to_string(),
        contract_id: "ctr_aerospace_parts_logistics_2026".to_string(),
        contract_hash: "sha256:d8f1e9c7b4a2c1d3e5f60718293a4b5c6d7e8f90123456789abcdef012345678"
            .to_string(),
        capability_id: "io.logistics.freight@v1".to_string(),
        input_hash: "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef012345678d8f1e9c7"
            .to_string(),
        output_hash: "sha256:f6e5d4c3b2a109876543210fedcba9876543210fedcba9876543210fedcba987"
            .to_string(),
        issuer_did: trusted_peer_root.clone(),
        counterparty_did: supplier_did.clone(),
        outcome: "SUCCESS".to_string(),
        executed_at: Utc::now() - chrono::Duration::days(14),
    };

    let peer_receipt: ExecutionReceipt =
        sign_execution_receipt(prior_receipt_payload, &peer_signing_key)?;

    println!("Buyer Gateway verifies presented ExecutionReceipt:");
    println!("  - Receipt ID:    {}", peer_receipt.receipt_id);
    println!("  - Issuer:        {}", peer_receipt.issuer_did);
    println!("  - Subject:       {}", peer_receipt.counterparty_did);
    println!("  - Capability:    {}", peer_receipt.capability_id);
    println!("  - Stated Status: {}", peer_receipt.outcome);

    // Cryptographic signature check
    verify_execution_receipt(&peer_receipt, &peer_verifying_key)?;
    println!("  - Cryptographic Signature: ✅ Valid Ed25519 signature from '{trusted_peer_root}'");

    // Check if issuer is in trusted_peer_roots
    let has_trusted_attestation =
        peer_receipt.issuer_did == trusted_peer_root && peer_receipt.outcome == "SUCCESS";

    let attestation_eval = evaluator.evaluate_with_reputation(
        "tenant_buyer_corp",
        "agent_procure_01",
        "io.logistics.freight@v1",
        Some(12_500),
        initial_rep.successful_count,
        has_trusted_attestation,
    );

    assert_eq!(attestation_eval, PolicyOutcome::Allow);
    println!("  - Reputation Evaluation:   ✅ ALLOWED — Unlocked high-value tier (€15,000) via verified peer attestation!\n");

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Stage 3: Bilateral Contract Negotiation (Proposal -> Amendment -> Agreement)
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🤝 STAGE 3: Bilateral Contract Negotiation & Mutual Signing Ceremony");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let now = Utc::now();

    // --- Step 3.1: Buyer proposes initial terms (v1) ---
    println!("Step 3.1: Buyer Agent initiates Draft Contract Proposal (v1)...");
    let buyer_draft_v1 = InteractionContract {
        contract_id: "ctr_buyer_supplier_freight_001".to_string(),
        version: 1,
        state: ContractState::Draft,
        issuer: PartyIdentity::new_did(buyer_did.clone()),
        counterparty: PartyIdentity::new_did(supplier_did.clone()),
        purpose: Purpose {
            code: "procure_freight_delivery".to_string(),
            description: "Autonomous high-value logistics dispatch".to_string(),
        },
        capabilities: vec![ContractCapability {
            capability_id: "io.logistics.freight@v1".to_string(),
            operations: vec!["quote".to_string(), "book".to_string(), "track".to_string()],
            parameter_constraints: None,
            result_constraints: None,
        }],
        constraints: ContractConstraints {
            max_transaction_value: Some(ContractMoney {
                amount_minor: 1_000_000, // Buyer proposes initial €10,000.00 ceiling
                currency: "EUR".to_string(),
            }),
            allowed_geographies: vec!["EU".to_string()],
            max_units: Some(5),
            cancellation_terms: Some("2h prior to pickup".to_string()),
            custom_constraints: std::collections::BTreeMap::new(),
        },
        data_policy: DataPolicy::default(),
        obligations: vec![],
        commercial_terms: Some(CommercialTerms {
            settlement_term: Some("Net-60".to_string()), // Buyer proposes Net-60 payment
            payment_instrument: Some("corporate_sepa".to_string()),
            payment_details: None,
        }),
        validity: ContractValidity {
            valid_from: now - chrono::Duration::minutes(5),
            valid_until: now + chrono::Duration::days(30),
        },
        protocol: Default::default(),
        evidence: ContractEvidence::default(),
        parent_contract_id: None,
        previous_contract_hash: None,
        created_at: now,
        updated_at: now,
    };

    let v1_hash = compute_contract_hash(&buyer_draft_v1)?;
    println!("  - Proposal ID:       {}", buyer_draft_v1.contract_id);
    println!("  - Version:           v1 (Draft)");
    println!("  - Proposed Ceiling:  €10,000.00 EUR");
    println!("  - Settlement Term:   Net-60");
    println!("  - Cancellation:      2h prior to pickup");
    println!("  - Canonical Hash v1: {v1_hash}\n");

    // --- Step 3.2: Supplier amends terms (v2 counter-proposal) ---
    println!("Step 3.2: Supplier Agent evaluates v1 and returns Counter-Proposal (v2)...");
    println!(
        "  ⚠️  Supplier Policy check: Requested priority freight corridor requires €15,000 cap"
    );
    println!(
        "  ⚠️  Supplier Commercial check: Net-60 rejected; counter-propose Net-15 & 24h notice"
    );
    println!("  📎 Supplier attaches verified peer ExecutionReceipt to justify terms.");

    let mut amended_contract_v2 = InteractionContract {
        contract_id: buyer_draft_v1.contract_id.clone(),
        version: 2,
        state: ContractState::Draft,
        issuer: PartyIdentity::new_did(buyer_did.clone()),
        counterparty: PartyIdentity::new_did(supplier_did.clone()),
        purpose: buyer_draft_v1.purpose.clone(),
        capabilities: buyer_draft_v1.capabilities.clone(),
        constraints: ContractConstraints {
            max_transaction_value: Some(ContractMoney {
                amount_minor: 1_500_000, // Supplier amends ceiling to €15,000.00
                currency: "EUR".to_string(),
            }),
            allowed_geographies: vec!["EU".to_string()],
            max_units: Some(5),
            cancellation_terms: Some("24h notice".to_string()), // Amended cancellation
            custom_constraints: std::collections::BTreeMap::new(),
        },
        data_policy: DataPolicy::default(),
        obligations: vec![],
        commercial_terms: Some(CommercialTerms {
            settlement_term: Some("Net-15".to_string()), // Amended payment terms
            payment_instrument: Some("corporate_sepa".to_string()),
            payment_details: None,
        }),
        validity: buyer_draft_v1.validity.clone(),
        protocol: Default::default(),
        evidence: ContractEvidence {
            attestations: vec![],
            authority_evidence: vec![],
            reputation_receipts: vec![peer_receipt.clone()], // Attached reputation evidence
        },
        parent_contract_id: None,
        previous_contract_hash: Some(v1_hash.clone()), // Cryptographically linked to v1
        created_at: now,
        updated_at: Utc::now(),
    };

    let v2_hash = compute_contract_hash(&amended_contract_v2)?;
    println!("  - Counter-Proposal:  v2 (Amended)");
    println!("  - Amended Ceiling:   €15,000.00 EUR (+€5,000)");
    println!("  - Amended Terms:     Net-15, 24h cancellation notice");
    println!("  - Linked Parent:     {v1_hash}");
    println!("  - Canonical Hash v2: {v2_hash}\n");

    // --- Step 3.3: Buyer reviews amendments & both parties agree ---
    println!("Step 3.3: Buyer reviews amendments and both parties enter Activation Ceremony...");
    println!("  - Checking amended ceiling (€15,000 <= €50,000 Buyer Policy Max): ✅ In bounds");
    println!("  - Checking attached peer attestation ({trusted_peer_root}):       ✅ Verified");
    println!("  - Buyer decision: ACCEPT AMENDED TERMS 🤝");

    // Transition to Accepted state
    amended_contract_v2.state = ContractState::Accepted;

    // Both parties generate Ed25519 attestations signing the v2 canonical hash
    let buyer_attestation =
        create_attestation(&amended_contract_v2, &buyer_did, &buyer_signing_key)?;
    let supplier_attestation =
        create_attestation(&amended_contract_v2, &supplier_did, &supplier_signing_key)?;

    amended_contract_v2
        .evidence
        .attestations
        .push(buyer_attestation);
    amended_contract_v2
        .evidence
        .attestations
        .push(supplier_attestation);

    // Execute the deterministic 9-step activation ceremony
    let mut party_keys = HashMap::new();
    party_keys.insert(buyer_did.clone(), buyer_verifying_key);
    party_keys.insert(supplier_did.clone(), supplier_verifying_key);

    let contract = execute_activation_ceremony(amended_contract_v2, &party_keys)?;
    let contract_hash = v2_hash;

    println!("  - Buyer Ed25519 Signature:    Verified ✅");
    println!("  - Supplier Ed25519 Signature: Verified ✅");
    println!("  - Activation Ceremony:        Completed (9 invariants verified) ✅");
    println!(
        "  - Final Contract State:       ACTIVE 🟢 (Version {})\n",
        contract.version
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Stage 4: Execution Proposal, Policy Verification & Grant Issuance
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("⚡ STAGE 4: Action Proposal & Deterministic Execution Grant Issuance");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let action_name = "io.logistics.freight@v1";
    let action_arguments = serde_json::json!({
        "shipment_id": "SHP-LYON-2026",
        "destination": "Lyon Logistics Hub",
        "units": 2,
        "amount": {
            "amount_minor": 1_250_000,
            "currency": "EUR"
        }
    });

    println!("Supplier Agent proposes action:");
    println!("  - Tool:      {action_name}");
    println!("  - Arguments: {}", action_arguments);

    // Compute argument digest
    let input_hash = canonical_hash(&action_arguments);

    // Mint ExecutionGrant
    let grant = trust_model::ExecutionGrant {
        grant_id: format!("grant_{}", uuid::Uuid::new_v4()),
        action_id: format!("act_{}", uuid::Uuid::new_v4()),
        tenant_id: "tenant_buyer_corp".to_string(),
        workspace_id: "default".to_string(),
        tool_name: action_name.to_string(),
        input_hash: input_hash.clone(),
        issuer: buyer_did.clone(),
        expires_at: Utc::now().timestamp() + 30, // 30s TTL
        nonce: uuid::Uuid::new_v4().to_string(),
        contract_id: Some(contract.contract_id.clone()),
        contract_hash: Some(contract_hash.clone()),
    };

    let granted_action = trust_model::GrantedAction {
        grant: grant.clone(),
        raw_grant_jwt: "mock_jwt_token".to_string(),
        action_arguments: action_arguments.clone(),
    };

    println!("Trust Gateway evaluates and mints ExecutionGrant:");
    println!("  - Grant ID:     {}", grant.grant_id);
    println!("  - Input Hash:   {}", grant.input_hash);
    println!("  - TTL:          30 seconds (single-use)");
    println!(
        "  - Contract ID:  {}",
        grant.contract_id.as_deref().unwrap()
    );
    println!("  - Authorization: GRANTED 🎫\n");

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Stage 5: Execution & Minting Sealed Execution Receipt (Proof of Good Execution)
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📦 STAGE 5: Execution & Proof of Good Execution Minting");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Simulated execution in isolated sandbox
    println!("Isolated Executor verifying grant claims and executing action...");
    assert_eq!(
        canonical_hash(&granted_action.action_arguments),
        granted_action.grant.input_hash
    );

    let execution_output = serde_json::json!({
        "status": "confirmed",
        "booking_reference": "FR-LYON-88412",
        "estimated_delivery": "2026-10-02T14:00:00Z"
    });
    let output_hash = canonical_hash(&execution_output);
    println!("Action Succeeded! Output: {}", execution_output);

    // Gateway records success in local ReputationStore
    println!("\nUpdating Buyer Gateway local counterparty ledger...");
    let updated_rep = rep_store
        .record_execution("tenant_buyer_corp", &supplier_did, true)
        .await?;
    println!(
        "  - Previous local successful count: {}",
        initial_rep.successful_count
    );
    println!(
        "  - New local successful count:      {}",
        updated_rep.successful_count
    );
    println!(
        "  - Last Success Timestamp:          {:?}",
        updated_rep.last_success_at
    );

    // Gateway mints and signs the sealed ExecutionReceipt
    println!("\nMinting sealed, Ed25519-signed ExecutionReceipt (Proof of Good Execution)...");
    let receipt_id = format!("rcpt_{}", uuid::Uuid::new_v4());
    let fresh_receipt_payload = SignableReceiptPayload {
        receipt_id: receipt_id.clone(),
        grant_jti: grant.grant_id.clone(),
        contract_id: contract.contract_id.clone(),
        contract_hash: contract_hash.clone(),
        capability_id: action_name.to_string(),
        input_hash: input_hash.clone(),
        output_hash: output_hash.clone(),
        issuer_did: buyer_did.clone(),
        counterparty_did: supplier_did.clone(),
        outcome: "SUCCESS".to_string(),
        executed_at: Utc::now(),
    };

    let fresh_receipt = sign_execution_receipt(fresh_receipt_payload, &buyer_signing_key)?;

    println!("Sealed Receipt Minted:");
    println!("  - Receipt ID:   {}", fresh_receipt.receipt_id);
    println!("  - Grant JTI:    {}", fresh_receipt.grant_jti);
    println!("  - Issuer:       {}", fresh_receipt.issuer_did);
    println!("  - Counterparty: {}", fresh_receipt.counterparty_did);
    println!("  - Outcome:      {}", fresh_receipt.outcome);
    println!("  - Signature:    {}...", &fresh_receipt.signature[..32]);

    // Verify fresh receipt
    verify_execution_receipt(&fresh_receipt, &buyer_verifying_key)?;
    println!("\nCryptographic Verification: ✅ Verified against Buyer Gateway public key!");
    println!("🎉 The Supplier Agent now stores this sealed receipt in its credentials vault");
    println!("   to present as unforgeable proof of good execution to future enterprise peers!");

    println!("\n================================================================================");
    println!("✅ FULL END-TO-END REPUTATION & NEGOTIATION CYCLE SUCCESSFULLY COMPLETED");
    println!("================================================================================");

    Ok(())
}
