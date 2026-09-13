pub mod adapters;
pub mod attestation;
pub mod canonical;
pub mod ceremony;
pub mod data_policy_eval;
pub mod delegation;
pub mod error;
pub mod hash;
pub mod model;
pub mod negotiation;
pub mod negotiation_service;
pub mod protocol_msg;
pub mod receipt;
pub mod state_machine;
pub mod store;
pub mod validation;

pub use adapters::translate_contract_action;
pub use attestation::{create_attestation, extract_pubkey_from_did, verify_attestation};
pub use canonical::{canonicalize_contract, canonicalize_signable_payload};
pub use ceremony::execute_activation_ceremony;
pub use data_policy_eval::evaluate_response_data_policy;
pub use delegation::{verify_contract_authorities, verify_delegated_authority};
pub use error::ContractError;
pub use hash::{compute_contract_hash, verify_contract_hash};
pub use model::{
    AuthorityReference, CapabilityBinding, CommercialTerms, ContractAttestation,
    ContractCapability, ContractConstraints, ContractContext, ContractEvidence, ContractMoney,
    ContractValidity, DataPolicy, ExecutionReceipt, InteractionContract, Obligation, PartyIdentity,
    ProtocolBinding, Purpose, SignableContractPayload, SignableReceiptPayload,
};
pub use negotiation::{ContractProposal, NegotiationLimits};
pub use negotiation_service::ContractNegotiationService;
pub use protocol_msg::NicpMessage;
pub use receipt::{compute_receipt_hash, sign_execution_receipt, verify_execution_receipt};
pub use state_machine::ContractState;
pub use store::{format_contract_key, ContractStore, InMemoryContractStore};
pub use validation::{
    validate_action_against_contract, validate_contract_structure, ActionEvaluationContext,
};
