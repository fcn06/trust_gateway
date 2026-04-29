use schemars::schema_for;
use std::fs;
use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn verify_snapshot<T: schemars::JsonSchema>(name: &str) {
        let schema = schema_for!(T);
        let schema_json = serde_json::to_string_pretty(&schema).unwrap();
        
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("snapshots");
        path.push(format!("{}.json", name));

        if !path.exists() {
            // Create initial snapshot if it doesn't exist
            fs::write(&path, &schema_json).expect("Failed to write initial snapshot");
            panic!("Snapshot created for {}. Please review and commit it.", name);
        }

        let existing_schema = fs::read_to_string(&path).expect("Failed to read snapshot");
        
        if existing_schema != schema_json {
            // If they differ, we fail and show the diff
            // In a real environment, we might want to use a diff library, 
            // but for now, we'll just show the new schema and panic.
            let mut new_path = path.clone();
            new_path.set_extension("new.json");
            fs::write(&new_path, &schema_json).ok();
            
            panic!(
                "Schema mismatch for {}. \n\
                 Existing: {}\n\
                 New: {}\n\
                 A new snapshot has been written to {:?}. If this change is intentional, replace the snapshot file.",
                name, path.display(), new_path.display(), new_path
            );
        }
    }

    #[test]
    fn snapshot_action_request() {
        verify_snapshot::<ActionRequest>("action_request");
    }

    #[test]
    fn snapshot_action_result() {
        verify_snapshot::<ActionResult>("action_result");
    }

    #[test]
    fn snapshot_approval_request() {
        verify_snapshot::<ApprovalRequest>("approval_request");
    }

    #[test]
    fn snapshot_audit_event() {
        verify_snapshot::<AuditEvent>("audit_event");
    }

    #[test]
    fn snapshot_execution_grant() {
        verify_snapshot::<ExecutionGrant>("execution_grant");
    }

    #[test]
    fn snapshot_actor_context() {
        verify_snapshot::<ActorContext>("actor_context");
    }
}
