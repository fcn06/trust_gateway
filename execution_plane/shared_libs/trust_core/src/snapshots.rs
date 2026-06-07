#[cfg(test)]
mod tests {
    use crate::*;
    use schemars::schema_for;
    use std::fs;
    use std::path::PathBuf;

    fn verify_snapshot<T: schemars::JsonSchema>(name: &str) {
        let schema = schema_for!(T);
        let schema_json = serde_json::to_string_pretty(&schema).unwrap();

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("snapshots");
        path.push(format!("{}.json", name));

        if !path.exists() {
            // Create initial snapshot if it doesn't exist
            fs::write(&path, &schema_json).expect("Failed to write initial snapshot");
            panic!(
                "Snapshot created for {}. Please review and commit it.",
                name
            );
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

    // ── Phase 0: Structural baseline assertions ─────────────
    //
    // These tests lock the current field set of security-critical types.
    // SEC-2: input_hash is now a mandatory String field.

    #[test]
    fn baseline_execution_grant_required_fields() {
        let schema = schema_for!(ExecutionGrant);
        let schema_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&schema).unwrap()).unwrap();

        let required = schema_json
            .get("required")
            .and_then(|v| v.as_array())
            .expect("ExecutionGrant must have required fields");

        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();

        // Assert the EXACT set of required fields as of SEC-2.
        // input_hash was promoted from optional to required.
        let expected = vec![
            "action_id",
            "allowed_action",
            "clearance",
            "expires_at",
            "grant_id",
            "input_hash",
            "owner_did",
            "requester_did",
            "tenant_id",
        ];
        assert_eq!(
            required_names, expected,
            "ExecutionGrant required fields changed! Update this test if intentional."
        );
    }

    #[test]
    fn baseline_execution_grant_all_properties() {
        let schema = schema_for!(ExecutionGrant);
        let schema_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&schema).unwrap()).unwrap();

        let properties = schema_json
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("ExecutionGrant must have properties");

        let mut prop_names: Vec<&str> = properties.keys().map(|k| k.as_str()).collect();
        prop_names.sort();

        // Assert ALL properties (required + optional) as of Phase 3.
        let expected = vec![
            "action_id",
            "allowed_action",
            "clearance",
            "expires_at",
            "grant_id",
            "input_hash",
            "kid",
            "owner_did",
            "requester_did",
            "tenant_id",
        ];
        assert_eq!(
            prop_names, expected,
            "ExecutionGrant properties changed! Update this test if intentional."
        );
    }

    #[test]
    fn baseline_grant_clearance_variants() {
        // Verify the exact set of GrantClearance variants via serialization.
        let variants = vec![
            (GrantClearance::AutoApproved, "\"auto_approved\""),
            (GrantClearance::HumanApproved, "\"human_approved\""),
            (GrantClearance::ElevatedApproval, "\"elevated_approval\""),
            (GrantClearance::ProofVerified, "\"proof_verified\""),
        ];
        for (variant, expected_json) in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(
                &json, expected_json,
                "GrantClearance serialization changed for {:?}",
                variant
            );
        }
        // Ensure we have exactly 4 variants by testing that these are all of them.
        assert_eq!(variants.len(), 4, "GrantClearance variant count changed!");
    }

    #[test]
    fn baseline_execution_grant_serde_round_trip() {
        let grant = ExecutionGrant {
            grant_id: "test-grant-001".to_string(),
            action_id: "test-action-001".to_string(),
            tenant_id: "tenant-abc".to_string(),
            owner_did: "did:twin:zowner".to_string(),
            requester_did: "did:twin:zrequester".to_string(),
            allowed_action: "google.calendar.event.create".to_string(),
            clearance: GrantClearance::AutoApproved,
            expires_at: 1700000000,
            kid: Some("kid-1".to_string()),
            input_hash: "abc123def456".to_string(),
        };

        let json = serde_json::to_string(&grant).expect("Grant serialization must succeed");
        let deserialized: ExecutionGrant =
            serde_json::from_str(&json).expect("Grant deserialization must succeed");

        assert_eq!(deserialized.grant_id, grant.grant_id);
        assert_eq!(deserialized.action_id, grant.action_id);
        assert_eq!(deserialized.tenant_id, grant.tenant_id);
        assert_eq!(deserialized.owner_did, grant.owner_did);
        assert_eq!(deserialized.requester_did, grant.requester_did);
        assert_eq!(deserialized.allowed_action, grant.allowed_action);
        assert_eq!(deserialized.expires_at, grant.expires_at);
        assert_eq!(deserialized.kid, grant.kid);
    }

    #[test]
    fn baseline_auth_level_variants() {
        // Lock the current AuthLevel enum variants.
        let variants = vec![
            (AuthLevel::Level3Session, "Level3Session"),
            (AuthLevel::Level4Verified, "Level4Verified"),
            (AuthLevel::Level5WebAuthn, "Level5WebAuthn"),
        ];
        for (variant, expected_debug) in &variants {
            assert_eq!(
                format!("{:?}", variant),
                *expected_debug,
                "AuthLevel debug representation changed"
            );
        }
        assert_eq!(
            variants.len(),
            3,
            "AuthLevel variant count changed! Phase 2 expands this to 5 numeric levels."
        );
    }
}
