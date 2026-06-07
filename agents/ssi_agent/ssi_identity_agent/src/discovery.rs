//! Discovery service registration module.
//!
//! Provides functionality for registering agents with discovery services
//! including retry logic with exponential backoff.

use agent_core::business_logic::services::DiscoveryService;
use agent_models::registry::registry_models::AgentDefinition;
use anyhow::Result;
use std::sync::Arc;

/// Register an agent with the discovery service.
/// 
/// Implements retry logic with exponential backoff. If registration fails
/// after max retries, the agent will still start but without discovery registration.
/// 
/// # Arguments
/// * `discovery_service` - Optional discovery service to register with
/// * `agent_definition` - The agent definition to register
/// 
/// # Returns
/// * `Ok(())` - Registration succeeded or was skipped (no discovery service configured)
pub async fn register_with_discovery_service(
    discovery_service: &Option<Arc<dyn DiscoveryService>>,
    agent_definition: &AgentDefinition,
) -> Result<()> {
    let max_retries = 2;
    let mut retries = 0;
    let mut delay = 1; // seconds

    if let Some(ds) = discovery_service {
        loop {
            let registration_result = ds.register_agent(agent_definition).await;

            match registration_result {
                Ok(_) => {
                    tracing::info!("Agent successfully registered with discovery service.");
                    break;
                }
                Err(e) => {
                    retries += 1;
                    if retries < max_retries {
                        tracing::warn!(
                            "Failed to register with discovery service, attempt {}/{}. Error: {}. Retrying in {} seconds...",
                            retries,
                            max_retries,
                            e,
                            delay
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        delay *= 2; // Exponential backoff
                    } else {
                        tracing::error!(
                            "Failed to register with discovery service after {} attempts. Error: {}. Proceeding without discovery service registration.",
                            max_retries,
                            e
                        );
                        // Allow the agent to start even if registration fails
                        return Ok(());
                    }
                }
            }
        }
    } else {
        tracing::warn!("Discovery service not configured. Skipping registration.");
    }
    Ok(())
}
