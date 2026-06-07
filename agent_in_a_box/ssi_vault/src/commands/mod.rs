//! Command pattern implementations for SSI Vault operations.
//!
//! Each command encapsulates a discrete vault operation with its inputs,
//! validation, and execution logic.

pub mod unlock_vault;
pub mod create_identity;
pub mod jwt;

// Re-exports for convenience
pub use unlock_vault::UnlockVaultCommand;
pub use create_identity::CreateIdentityCommand;
pub use jwt::{IssueSessionJwtCommand, VerifySessionJwtCommand};

/// Trait for vault command execution.
/// 
/// Each command struct implements this trait to provide a consistent
/// execution interface across all vault operations.
pub trait VaultCommand {
    type Output;
    
    /// Execute the command and return the result.
    fn execute(&self) -> Result<Self::Output, String>;
}

