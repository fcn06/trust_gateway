# Egress PII & Secret Sanitization Example

This example demonstrates output filtering, regex redaction, and structured DLP field classification using `trust_core::egress_filter` and `crates/trust-egress`.

---

## What This Demonstrates

1. **Regex-Based Text Scrubbing**:
   - Conservative replacement of emails, phone numbers, credit card numbers, Bearer tokens, OpenAI API keys, Stripe secrets, and AWS credentials.
2. **Recursive JSON Tree Scrubbing**:
   - Walks arbitrary nested JSON objects and arrays, scrubbing sensitive string values while preserving schema structure and non-string types.
3. **Audience-Aware Structured DLP**:
   - Classifies fields into security categories (`PiiContact`, `InternalIdentifier`, `BusinessConfidential`, `PublicData`) and dynamically scrubs based on caller audience permissions (e.g. `external` vs `internal_admin`).

---

## Running the Example

```bash
cargo run -p egress-sanitization-example
```
