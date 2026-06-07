use crate::grant::ExecutionGrant;

/// Proof that a grant was cryptographically verified.
/// Only a GrantValidator can construct this (or via specialized constructors).
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    pub(crate) inner: ExecutionGrant,
}

impl VerifiedGrant {
    /// Create a new VerifiedGrant. 
    /// In production, this should only be called after verifying the signature.
    pub fn new(inner: ExecutionGrant) -> Self {
        Self { inner }
    }

    pub fn grant_id(&self) -> &str { &self.inner.grant_id }
    pub fn action_id(&self) -> &str { &self.inner.action_id }
    pub fn tenant_id(&self) -> &str { &self.inner.tenant_id }
    pub fn owner_did(&self) -> &str { &self.inner.owner_did }
    pub fn allowed_action(&self) -> &str { &self.inner.allowed_action }
    pub fn input_hash(&self) -> &str { &self.inner.input_hash }
}

/// Core interface for tool/skill execution.
///
/// This trait is the unified bridge between the Trust Gateway (which verifies policies)
/// and the various execution environments (MCP, Native Skills, VPs).
#[async_trait::async_trait]
pub trait Executor: Send + Sync {
    /// Human-readable name of the executor (e.g., "native-skill", "connector").
    fn name(&self) -> &str;

    /// Returns true if this executor can handle the given tool ID.
    fn handles(&self, tool_id: &str) -> bool;

    /// Executes the action authorized by the verified grant.
    ///
    /// The `VerifiedGrant` ensures that the execution path is only reached after
    /// strict policy validation and cryptographic verification.
    async fn execute(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, crate::errors::TrustError>;
}
