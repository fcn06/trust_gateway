// ─────────────────────────────────────────────────────────────
// JetStream Approval Store — implements trust_core::traits::ApprovalStore
//
// Default community implementation that publishes approval records
// to NATS JetStream KeyValue store ("approval_records").
// ─────────────────────────────────────────────────────────────

use trust_core::approval::{ApprovalRecord, ApprovalRequest, ApprovalResult, ApprovalStatus};
use trust_core::errors::StoreError;

pub struct JetStreamApprovalStore {
    js: async_nats::jetstream::Context,
}

impl JetStreamApprovalStore {
    pub fn new(js: async_nats::jetstream::Context) -> Self {
        Self { js }
    }

    async fn get_store(&self) -> Result<async_nats::jetstream::kv::Store, StoreError> {
        self.js
            .get_key_value("approval_records")
            .await
            .map_err(|e| StoreError::Backend(format!("KV lookup failed: {}", e)))
    }
}

#[async_trait::async_trait]
impl trust_core::traits::ApprovalStore for JetStreamApprovalStore {
    async fn create(&self, req: ApprovalRequest) -> Result<ApprovalRecord, StoreError> {
        let store = self.get_store().await?;
        
        let record = ApprovalRecord {
            approval_id: req.approval_id.clone(),
            action_id: req.action_id,
            tenant_id: req.tenant_id,
            tier: req.tier,
            reason: req.reason,
            status: if req.proof_required {
                ApprovalStatus::PendingProof
            } else {
                ApprovalStatus::Pending
            },
            resolved_by: None,
            resolution_method: None,
            requested_at: req.requested_at,
            resolved_at: None,
            action_request: req.action_request,
        };

        let json = serde_json::to_vec(&record)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        store
            .put(&record.approval_id, json.into())
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        Ok(record)
    }

    async fn get(&self, id: &str) -> Result<Option<ApprovalRecord>, StoreError> {
        let store = self.get_store().await?;
        
        if let Some(entry) = store.get(id).await.map_err(|e| StoreError::Backend(e.to_string()))? {
            let record = serde_json::from_slice::<ApprovalRecord>(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn mark_approved(&self, id: &str, result: ApprovalResult) -> Result<(), StoreError> {
        let store = self.get_store().await?;
        
        if let Some(mut record) = self.get(id).await? {
            record.status = ApprovalStatus::Approved;
            record.resolved_by = Some(result.resolved_by);
            record.resolution_method = Some(result.resolution_method);
            record.resolved_at = Some(result.resolved_at);

            let json = serde_json::to_vec(&record)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            store
                .put(id, json.into())
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            
            Ok(())
        } else {
            Err(StoreError::NotFound { id: id.to_string() })
        }
    }

    async fn mark_denied(&self, id: &str, result: ApprovalResult) -> Result<(), StoreError> {
        let store = self.get_store().await?;
        
        if let Some(mut record) = self.get(id).await? {
            record.status = ApprovalStatus::Denied;
            record.resolved_by = Some(result.resolved_by);
            record.resolution_method = Some(result.resolution_method);
            record.resolved_at = Some(result.resolved_at);

            let json = serde_json::to_vec(&record)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            store
                .put(id, json.into())
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            
            Ok(())
        } else {
            Err(StoreError::NotFound { id: id.to_string() })
        }
    }

    async fn mark_executed(&self, id: &str) -> Result<(), StoreError> {
        let store = self.get_store().await?;
        
        if let Some(mut record) = self.get(id).await? {
            record.status = ApprovalStatus::Executed;

            let json = serde_json::to_vec(&record)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            store
                .put(id, json.into())
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            
            Ok(())
        } else {
            Err(StoreError::NotFound { id: id.to_string() })
        }
    }

    async fn mark_execution_failed(&self, id: &str, error: &str) -> Result<(), StoreError> {
        let store = self.get_store().await?;
        
        if let Some(mut record) = self.get(id).await? {
            record.status = ApprovalStatus::ExecutionFailed;
            // Store the error in resolution_method for diagnostics
            record.resolution_method = Some(format!("execution_failed: {}", error));

            let json = serde_json::to_vec(&record)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;

            store
                .put(id, json.into())
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            
            Ok(())
        } else {
            Err(StoreError::NotFound { id: id.to_string() })
        }
    }

    async fn list_pending(&self, tenant_id: &str) -> Result<Vec<ApprovalRecord>, StoreError> {
        let store = self.get_store().await?;
        let mut records = Vec::new();

        use futures::StreamExt;
        let mut keys = store.keys().await.map_err(|e| StoreError::Backend(e.to_string()))?;
        
        let mut keys_vec = Vec::new();
        while let Some(key_res) = keys.next().await {
            if let Ok(key) = key_res {
                keys_vec.push(key);
            }
        }

        for key in keys_vec {
            if let Ok(Some(entry)) = store.get(&key).await {
                if let Ok(record) = serde_json::from_slice::<ApprovalRecord>(&entry) {
                    if (record.status == ApprovalStatus::Pending || record.status == ApprovalStatus::PendingProof) 
                        && record.tenant_id == tenant_id {
                        records.push(record);
                    }
                }
            }
        }

        Ok(records)
    }
}

