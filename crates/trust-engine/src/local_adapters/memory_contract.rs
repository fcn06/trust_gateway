use crate::traits::{ContractRegistry, EngineError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use trust_sdk::contracts::SignedContract;

#[derive(Default)]
pub struct InMemoryContractRegistry {
    contracts: RwLock<HashMap<String, SignedContract>>,
    skill_index: RwLock<HashMap<String, String>>, // skill_id -> contract_id
}

impl InMemoryContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ContractRegistry for InMemoryContractRegistry {
    async fn register_contract(&self, contract: SignedContract) -> Result<(), EngineError> {
        let mut contracts = self.contracts.write().map_err(|e| {
            EngineError::Internal(format!("RwLock poison: {e}"))
        })?;
        let mut skill_index = self.skill_index.write().map_err(|e| {
            EngineError::Internal(format!("RwLock poison: {e}"))
        })?;

        skill_index.insert(contract.skill_id.clone(), contract.contract_id.clone());
        contracts.insert(contract.contract_id.clone(), contract);
        Ok(())
    }

    async fn get_contract(
        &self,
        contract_id: &str,
    ) -> Result<Option<SignedContract>, EngineError> {
        let contracts = self.contracts.read().map_err(|e| {
            EngineError::Internal(format!("RwLock poison: {e}"))
        })?;
        Ok(contracts.get(contract_id).cloned())
    }

    async fn get_contract_for_skill(
        &self,
        _tenant_id: &str,
        skill_id: &str,
    ) -> Result<Option<SignedContract>, EngineError> {
        let skill_index = self.skill_index.read().map_err(|e| {
            EngineError::Internal(format!("RwLock poison: {e}"))
        })?;

        if let Some(cid) = skill_index.get(skill_id) {
            let contracts = self.contracts.read().map_err(|e| {
                EngineError::Internal(format!("RwLock poison: {e}"))
            })?;
            return Ok(contracts.get(cid).cloned());
        }

        // Try tool name suffix match
        let contracts = self.contracts.read().map_err(|e| {
            EngineError::Internal(format!("RwLock poison: {e}"))
        })?;
        for c in contracts.values() {
            if c.skill_id == skill_id || c.skill_id.ends_with(&format!(".{skill_id}@v1")) {
                return Ok(Some(c.clone()));
            }
        }

        Ok(None)
    }
}

