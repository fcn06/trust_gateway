use crate::approval::ApprovalManager;
use crate::auth::{AuthVerifier, TokenVerifier};
use crate::call_chain::{self, CallChainPolicy};
use crate::egress::EgressProcessor;
use crate::policy::PolicyEngine;
use crate::traits::*;
use ed25519_dalek::VerifyingKey;
use jwt_simple::prelude::Ed25519KeyPair;
use std::sync::Arc;
use tokio::sync::RwLock;
use trust_sdk::canonical::canonical_hash;
use trust_sdk::grants::{sign_grant_jwt, ExecutionGrant, GrantClearance};
use trust_sdk::model::*;

#[derive(Clone)]
pub enum TenancyMode {
    Single,
    Multi(Arc<dyn TenantResolver>),
}

pub struct TrustEngine {
    pub tenancy_mode: TenancyMode,
    pub signing_key_pair: Ed25519KeyPair,
    pub root_verifying_key: Option<VerifyingKey>,
    pub token_verifier: Option<Arc<dyn TokenVerifier>>,
    pub policy_engine: Arc<PolicyEngine>,
    pub skill_registry: Arc<dyn SkillRegistry>,
    pub nonce_store: Arc<dyn NonceStore>,
    pub taint_lineage_engine: Arc<dyn TaintAndLineageEngine>,
    pub reputation_evaluator: Arc<dyn ReputationEvaluator>,
    pub settlement_engine: Arc<dyn EconomicSettlementEngine>,
    pub dispatcher: Arc<dyn ExecutorDispatcher>,
    pub audit_sink: Arc<dyn AuditSink>,
    pub approval_manager: Arc<ApprovalManager>,
    pub tracked_call_chains: Arc<RwLock<std::collections::HashMap<String, CallChainContext>>>,
    pub configured_api_keys: Vec<String>,
}

pub struct DefaultReputationEvaluator;

#[async_trait::async_trait]
impl ReputationEvaluator for DefaultReputationEvaluator {
    async fn evaluate_counterparty(
        &self,
        _tenant_id: &str,
        _caller_did: &str,
        _skill: &trust_sdk::manifest::SkillManifest,
        _receipts: &[trust_sdk::receipts::ExecutionReceipt],
    ) -> Result<ReputationDecision, EngineError> {
        Ok(ReputationDecision::default())
    }

    async fn record_outcome(
        &self,
        _tenant_id: &str,
        _caller_did: &str,
        _provider_did: &str,
        _success: bool,
    ) -> Result<(), EngineError> {
        Ok(())
    }
}

pub struct DefaultSettlementEngine;

#[async_trait::async_trait]
impl EconomicSettlementEngine for DefaultSettlementEngine {
    async fn reserve_budget(
        &self,
        _tenant_id: &str,
        _payer_did: &str,
        _skill: &trust_sdk::manifest::SkillManifest,
    ) -> Result<Option<EconomicClaim>, EngineError> {
        Ok(None)
    }

    async fn settle_reservation(
        &self,
        _reservation_id: &str,
        _outcome: &Result<ExecutionResult, EngineError>,
    ) -> Result<Option<trust_sdk::receipts::ExecutionReceipt>, EngineError> {
        Ok(None)
    }
}

impl TrustEngine {
    /// Executes the 13-step pipeline strictly in order as specified in §8.3
    pub async fn propose_and_execute(
        &self,
        auth_header: &str,
        envelope: TrustEnvelope<ProposedAction>,
    ) -> Result<ExecutionResult, EngineError> {
        let action = &envelope.payload;
        let trace_id = &envelope.trace_id;

        // Step 1: Authenticate -> VerifiedJwt
        let verified_jwt = AuthVerifier::verify_bearer(
            auth_header,
            self.token_verifier.as_deref(),
            &self.configured_api_keys,
        )
        .await?;

        // Step 2: Tenant resolution (Mono-tenant guard: must be "default" in Single mode)
        let tenant_id = if !action.tenant_id.is_empty() {
            &action.tenant_id
        } else {
            verified_jwt.tenant_id()
        };

        match &self.tenancy_mode {
            TenancyMode::Single => {
                if tenant_id != "default" {
                    return Err(EngineError::UnauthorizedTenant(tenant_id.to_string()));
                }
            }
            TenancyMode::Multi(resolver) => {
                resolver.resolve_tenant(tenant_id).await?;
            }
        }

        // Step 3: Layer 0 Call-Chain Guard
        let mut chain_lock = self.tracked_call_chains.write().await;
        let tracked_ctx = chain_lock.get(trace_id);
        let mut active_ctx =
            call_chain::validate_context_integrity(action.call_chain.as_ref(), tracked_ctx)?;

        let chain_policy = CallChainPolicy::default();
        call_chain::evaluate_and_advance(&mut active_ctx, &action.tool_name, &chain_policy)?;
        chain_lock.insert(trace_id.clone(), active_ctx.clone());
        drop(chain_lock);

        // Step 4: Registry lookup
        let skill = self
            .skill_registry
            .get_skill(tenant_id, &action.tool_name)
            .await?
            .ok_or_else(|| EngineError::SkillNotFound(action.tool_name.clone()))?;

        // Step 5: ReputationEvaluator
        let rep_decision = self
            .reputation_evaluator
            .evaluate_counterparty(tenant_id, verified_jwt.subject(), &skill, &[])
            .await?;

        // Step 6: TaintAndLineageEngine::evaluate_taint_and_lineage
        let taint_decision = self
            .taint_lineage_engine
            .evaluate_taint_and_lineage(tenant_id, trace_id, &skill, &action.arguments)
            .await?;

        // Step 7: policy.toml evaluation (tier resolution; taint/reputation can only tighten)
        let base_decision =
            self.policy_engine
                .evaluate_with_auth_level(action, &skill, verified_jwt.auth_level());
        let mut effective_tier = base_decision.tier;

        if let Some(rep_tier) = rep_decision.tier_override {
            if rep_tier > effective_tier {
                effective_tier = rep_tier;
            }
        }

        let mut require_approval_reason = None;
        match taint_decision {
            TaintDecision::DowngradeToHumanApproval { reason } => {
                if effective_tier < Tier::Tier1RequireHumanApproval {
                    effective_tier = Tier::Tier1RequireHumanApproval;
                }
                require_approval_reason = Some(reason);
            }
            TaintDecision::DenyLineageViolation {
                argument,
                expected_sources,
            } => {
                return Err(EngineError::LineageViolation {
                    argument,
                    expected_sources,
                });
            }
            TaintDecision::Allow => {
                // Lineage cryptographic allow
            }
        }

        if effective_tier == Tier::Tier3Deny {
            return Err(EngineError::ActionDenied(base_decision.reason));
        }

        // Step 8: Human approval if required
        if effective_tier >= Tier::Tier1RequireHumanApproval {
            let reason = require_approval_reason.unwrap_or(base_decision.reason);
            let approval_record = self
                .approval_manager
                .create_request(action.clone(), reason.clone())
                .await?;
            return Err(EngineError::ApprovalRequired {
                action_id: action.action_id.clone(),
                approval_id: approval_record.approval_id,
                reason,
            });
        }

        // Step 9: EconomicSettlementEngine::reserve_budget
        let economic_claim = self
            .settlement_engine
            .reserve_budget(tenant_id, verified_jwt.subject(), &skill)
            .await?;

        // Step 10: Mint Ed25519 ExecutionGrant; audit
        let now = chrono::Utc::now().timestamp();
        let input_hash = canonical_hash(&action.arguments);
        let grant_jti = format!("grant_{}", uuid::Uuid::new_v4());

        let grant = ExecutionGrant {
            jti: grant_jti.clone(),
            action_id: action.action_id.clone(),
            tenant_id: tenant_id.to_string(),
            workspace_id: action.workspace_id.clone(),
            tool_name: skill.name.clone(),
            input_hash,
            iss: "trust_gateway".to_string(),
            exp: now + 30,
            policy_fingerprint: self.policy_engine.fingerprint().to_string(),
            clearance: GrantClearance::AutoApproved,
            economic_claim: economic_claim.clone(),
            budget: None,
            contract_id: None,
            contract_hash: None,
            lineage_attestation: None,
        };

        let aud = "executor-host";
        let grant_jwt = sign_grant_jwt(&grant, aud, &self.signing_key_pair)?;

        self.audit_sink
            .append(AuditEvent {
                event_id: format!("ev_{}", uuid::Uuid::new_v4()),
                timestamp: now,
                event_type: "grant_issued".to_string(),
                tenant_id: tenant_id.to_string(),
                trace_id: trace_id.to_string(),
                action_id: Some(action.action_id.clone()),
                details: serde_json::json!({
                    "jti": grant_jti,
                    "tool": skill.name,
                    "tier": effective_tier.to_string(),
                }),
                prev_hash: None,
                hash: None,
            })
            .await?;

        // Step 11: Dispatcher::dispatch (nonce consumed at executor boundary)
        self.nonce_store
            .consume_nonce(tenant_id, &grant.jti, 35)
            .await?;
        let dispatch_result = self
            .dispatcher
            .dispatch(&skill, &envelope, &grant_jwt)
            .await;

        // Step 12: Record tool output into lineage engine on the RAW result first,
        // then run egress PII redaction + structural validation.
        let raw_outcome = match dispatch_result {
            Ok(res) => {
                let _ = self
                    .taint_lineage_engine
                    .record_tool_output(tenant_id, trace_id, &skill, &res.output)
                    .await;

                // Egress PII redaction and structural validation
                let processed_output = EgressProcessor::process_egress(&res.output, &skill.egress)?;
                Ok(ExecutionResult {
                    output: processed_output,
                    ..res
                })
            }
            Err(e) => Err(e),
        };

        // Step 13: settle_reservation, record_outcome, audit
        let reservation_id = economic_claim
            .as_ref()
            .map(|c| c.reservation_id.as_str())
            .unwrap_or("none");
        let receipt = self
            .settlement_engine
            .settle_reservation(reservation_id, &raw_outcome)
            .await?;

        let success = raw_outcome.is_ok();
        let _ = self
            .reputation_evaluator
            .record_outcome(
                tenant_id,
                verified_jwt.subject(),
                &skill.author_did,
                success,
            )
            .await;

        let end_now = chrono::Utc::now().timestamp();
        self.audit_sink
            .append(AuditEvent {
                event_id: format!("ev_{}", uuid::Uuid::new_v4()),
                timestamp: end_now,
                event_type: "execution_completed".to_string(),
                tenant_id: tenant_id.to_string(),
                trace_id: trace_id.to_string(),
                action_id: Some(action.action_id.clone()),
                details: serde_json::json!({
                    "success": success,
                    "has_receipt": receipt.is_some(),
                }),
                prev_hash: None,
                hash: None,
            })
            .await?;

        raw_outcome
    }
}
