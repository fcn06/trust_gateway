use std::collections::HashMap;
use trust_core::egress_filter::{
    redact, redact_json, FieldSecurityClass, StructuredFieldClassifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("🔒 Trust Gateway Example: Egress PII & Secret Sanitization");
    println!("============================================================\n");

    // -------------------------------------------------------------
    // Scenario 1: Regex-Based Unstructured Text Scrubbing
    // -------------------------------------------------------------
    println!("--- 1. Unstructured Text Scrubbing ---");
    let raw_agent_response = "\
Hello Alice! We sent confirmation to alice.smith@enterprise.org and billed card 4532-1234-5678-9012. \
For reference, your support engineer used Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dummy and \
the backend secret was sk-live_abcdef1234567890abcdef123456.";

    println!("Raw Unsanitized Text from Tool:");
    println!("  \"{raw_agent_response}\"\n");

    let sanitized_text = redact(raw_agent_response);
    println!("Sanitized Text Egress Output:");
    println!("  \"{sanitized_text}\"\n");

    assert!(!sanitized_text.contains("alice.smith@enterprise.org"));
    assert!(!sanitized_text.contains("4532-1234-5678-9012"));
    assert!(!sanitized_text.contains("sk-live_"));
    println!("  ✅ Email, Credit Card, and API Keys completely scrubbed.\n");

    // -------------------------------------------------------------
    // Scenario 2: Recursive JSON Tree Scrubbing
    // -------------------------------------------------------------
    println!("--- 2. Recursive JSON Tree Scrubbing ---");
    let mut raw_json = serde_json::json!({
        "status": "success",
        "customer": {
            "name": "Bob Jones",
            "contact_email": "bob.jones@vendor.corp",
            "phone": "+1-415-555-0199",
            "api_credential": "Bearer topsecrettokenvalue123456"
        },
        "order_details": {
            "order_id": "ord_882194",
            "notes": "Refund approved by admin@payment.com with auth key sk-antigravitykey123456789012"
        }
    });

    println!("Raw JSON Payload (prior to egress):");
    println!("{}", serde_json::to_string_pretty(&raw_json)?);

    redact_json(&mut raw_json);

    println!("\nScrubbed JSON Payload (egress boundary):");
    println!("{}", serde_json::to_string_pretty(&raw_json)?);
    println!("  ✅ All nested string values cleansed recursively.\n");

    // -------------------------------------------------------------
    // Scenario 3: Structured DLP Field Classification
    // -------------------------------------------------------------
    println!("--- 3. Audience-Aware Structured DLP Field Redaction ---");
    let mut db_record = serde_json::json!({
        "account_id": "acc_7721",
        "email": "cfo@partner.corp",
        "internal_server_ip": "10.0.4.15",
        "revenue_forecast": "€1,200,000",
        "public_catalog_id": "cat_alpha_01"
    });

    let mut schema = HashMap::new();
    schema.insert("email".to_string(), FieldSecurityClass::PiiContact);
    schema.insert(
        "internal_server_ip".to_string(),
        FieldSecurityClass::InternalIdentifier,
    );
    schema.insert(
        "revenue_forecast".to_string(),
        FieldSecurityClass::BusinessConfidential,
    );
    schema.insert(
        "public_catalog_id".to_string(),
        FieldSecurityClass::PublicData,
    );

    println!("Redacting for 'external' audience:");
    StructuredFieldClassifier::filter_structured_json(&mut db_record, &schema, "external");
    println!("{}", serde_json::to_string_pretty(&db_record)?);

    assert_eq!(
        db_record["email"],
        serde_json::json!("[REDACTED:pii_contact]")
    );
    assert_eq!(
        db_record["internal_server_ip"],
        serde_json::json!("[REDACTED:internal_id]")
    );
    assert_eq!(
        db_record["revenue_forecast"],
        serde_json::json!("[REDACTED:confidential]")
    );
    assert_eq!(db_record["public_catalog_id"], "cat_alpha_01");

    println!("\n  ✅ Classified confidential fields redacted based on external audience role.");

    println!("\n============================================================");
    println!("🎉 All Egress Sanitization and Redaction features verified!");
    println!("============================================================");

    Ok(())
}
