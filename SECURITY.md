# Security Audit Notes

## JWT Verification Audit (April 2026)

An audit was performed to verify the usage of JWT extraction functions across the Lianxi codebase, specifically focusing on `extract_jti_from_jwt` and `decode_jwt_claims`.

**Findings:**
- `decode_jwt_claims` (and its wrapper functions like `extract_jti_from_jwt`) correctly decode the payload section without performing cryptographic signature validation.
- All instances of `decode_jwt_claims` and `extract_jti_from_jwt` across `trust_gateway`, `agent_in_a_box/host`, and `ssi_mcp_runtime` were reviewed.
- None of these functions are used for making authorization decisions. They are strictly used for identity extraction, correlation (JTI nonce store), and auditing purposes.
- All authorization decisions are correctly delegated to the `ssi_vault` or upstream identity providers where signature verification occurs.

**Action Taken:**
- Added a `#[must_use]` attribute to all JWT extraction functions in `identity_context` to prevent accidental misuse.
- Added explicit documentation to `decode_jwt_claims` warning developers that the function does not verify signatures and that `ssi_vault` must be used for authorization.
