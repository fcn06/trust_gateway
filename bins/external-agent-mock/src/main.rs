use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use tokio::sync::Mutex;
use trust_sdk::canonical::canonical_hash;
use trust_sdk::manifest::{
    DataOriginTrust, EgressClassification, ExecutionSpec, PolicyDefaults, RemoteSkillPublication,
    RuntimeType, SkillManifest, SkillVisibility,
};
use trust_sdk::receipts::{extract_grant_jti_unverified, sign_provider_execution_outcome};

#[derive(Parser, Debug)]
#[command(
    name = "external-agent-mock",
    about = "External Agent Simulation Daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Serve the external agent HTTP endpoint hosting /.well-known/did.json and /skills/execute
    Serve {
        #[arg(long, default_value_t = 4025)]
        port: u16,
        #[arg(long, default_value_t = 77)]
        seed: u8,
    },
    /// Publish the agent's tool to Trust Gateway using dynamic DID resolution
    Publish {
        #[arg(long, default_value_t = 4025)]
        port: u16,
        #[arg(long, default_value_t = 77)]
        seed: u8,
        #[arg(long, default_value = "http://localhost:8081")]
        gateway_url: String,
    },
    /// Display the generated W3C DID document for this agent
    InspectDid {
        #[arg(long, default_value_t = 4025)]
        port: u16,
        #[arg(long, default_value_t = 77)]
        seed: u8,
    },
}

#[derive(Clone)]
struct AppState {
    did: String,
    public_key_hex: String,
    signing_key: SigningKey,
    port: u16,
    execution_counter: Arc<Mutex<u64>>,
}

fn build_agent_identity(port: u16, seed: u8) -> (SigningKey, String, String) {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    let did = format!("did:web:127.0.0.1%3A{port}");
    (signing_key, verifying_key_to_did_key(&did), public_key_hex)
}

fn verifying_key_to_did_key(did: &str) -> String {
    did.to_string()
}

fn build_did_doc(did: &str, public_key_hex: &str, port: u16) -> serde_json::Value {
    let key_id = format!("{did}#key-1");
    serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyHex": public_key_hex
        }],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "service": [{
            "id": format!("{did}#service-1"),
            "type": "SkillExecutionService",
            "serviceEndpoint": format!("http://127.0.0.1:{port}/skills/execute")
        }]
    })
}

async fn handle_did_json(State(state): State<AppState>) -> impl IntoResponse {
    let doc = build_did_doc(&state.did, &state.public_key_hex, state.port);
    (StatusCode::OK, Json(doc))
}

async fn handle_execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut count = state.execution_counter.lock().await;
    *count += 1;

    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("<missing>");

    println!(
        "\n[Agent A Service] === INCOMING EXECUTION DISPATCH (#{}) ===",
        *count
    );
    println!("[Agent A Service] Header Authorization: {auth_header}");
    println!(
        "[Agent A Service] Payload: {}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );

    let amount = payload
        .pointer("/action/arguments/amount")
        .and_then(|v| v.as_f64())
        .unwrap_or(100.0);

    let from = payload
        .pointer("/action/arguments/from")
        .and_then(|v| v.as_str())
        .unwrap_or("USD");

    let to = payload
        .pointer("/action/arguments/to")
        .and_then(|v| v.as_str())
        .unwrap_or("EUR");

    let rate = match (from, to) {
        ("USD", "EUR") => 0.92,
        ("EUR", "USD") => 1.087,
        ("USD", "GBP") => 0.79,
        ("GBP", "USD") => 1.265,
        _ => 1.0,
    };

    let converted = amount * rate;

    let action_id = payload
        .pointer("/action/action_id")
        .and_then(|v| v.as_str())
        .unwrap_or("act-default");

    let grant_jwt = payload
        .get("grant")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let grant_jti =
        extract_grant_jti_unverified(grant_jwt).unwrap_or_else(|| format!("grant_for_{action_id}"));

    let response = serde_json::json!({
        "status": "completed",
        "action_id": action_id,
        "source_currency": from,
        "target_currency": to,
        "original_amount": amount,
        "exchange_rate": rate,
        "converted_amount": converted,
        "provider_agent": state.did,
        "execution_timestamp": chrono::Utc::now().to_rfc3339()
    });

    let provider_sig = sign_provider_execution_outcome(
        action_id,
        &grant_jti,
        &response,
        "success",
        &state.signing_key,
    );

    println!(
        "[Agent A Service] Completed execution -> Converted: {converted} {to} (Signed Receipt: {}...)",
        &provider_sig[..16]
    );

    let mut resp_headers = HeaderMap::new();
    if let Ok(val) = provider_sig.parse() {
        resp_headers.insert("x-lianxi-provider-signature", val);
    }

    (StatusCode::OK, resp_headers, Json(response))
}

fn build_skill_manifest(did: &str) -> SkillManifest {
    SkillManifest {
        schema_version: "lianxi.skill/v1".to_string(),
        id: "io.lianxi.skill.fintech_converter@v1".to_string(),
        name: "fintech_currency_converter".to_string(),
        version: "1.0.0".to_string(),
        description: "Institutional real-time currency conversion tool operated by Agent A"
            .to_string(),
        author_did: did.to_string(),
        data_origin_trust: DataOriginTrust::VerifiedPartner,
        lineage_rules: vec![],
        execution: ExecutionSpec {
            runtime: RuntimeType::BoundedHttp,
            entrypoint: "skills/execute".to_string(),
            timeout_secs: 15,
            memory_limit_mb: 256,
            allowed_interpreters: vec![],
        },
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "amount": { "type": "number", "description": "Amount to convert" },
                "from": { "type": "string", "description": "Source 3-letter currency code (e.g. USD)" },
                "to": { "type": "string", "description": "Target 3-letter currency code (e.g. EUR)" }
            },
            "required": ["amount", "from", "to"]
        }),
        policy_defaults: PolicyDefaults {
            default_tier: "tier0_auto".to_string(),
            max_frequency_per_trace: 20,
            default_risk_level: "low".to_string(),
            operation_kind: "read".to_string(),
        },
        egress: EgressClassification {
            contains_pii: false,
            max_payload_bytes: 65536,
            allowed_fields: vec![],
        },
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::InspectDid { port, seed } => {
            let (_, did, pubkey_hex) = build_agent_identity(port, seed);
            let doc = build_did_doc(&did, &pubkey_hex, port);
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        Commands::Serve { port, seed } => {
            let (signing_key, did, pubkey_hex) = build_agent_identity(port, seed);
            let state = AppState {
                did: did.clone(),
                public_key_hex: pubkey_hex,
                signing_key,
                port,
                execution_counter: Arc::new(Mutex::new(0)),
            };

            let app = Router::new()
                .route("/.well-known/did.json", get(handle_did_json))
                .route("/skills/execute", post(handle_execute))
                .with_state(state);

            let addr = format!("0.0.0.0:{port}");
            println!("\n╔═════════════════════════════════════════════════════════════════╗");
            println!("║  External Agent (Tenant A) Simulation Service                    ║");
            println!("╠═════════════════════════════════════════════════════════════════╣");
            println!("║ Agent DID:         {:<44} ║", did);
            println!(
                "║ Service Endpoint:  http://127.0.0.1:{:<5}/skills/execute       ║",
                port
            );
            println!(
                "║ DID Document:      http://127.0.0.1:{:<5}/.well-known/did.json  ║",
                port
            );
            println!("║ Status:            LISTENING on {:<31} ║", addr);
            println!("╚═════════════════════════════════════════════════════════════════╝\n");

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Publish {
            port,
            seed,
            gateway_url,
        } => {
            let (signing_key, did, _) = build_agent_identity(port, seed);
            let manifest = build_skill_manifest(&did);

            // Canonical hash and Ed25519 signature
            let manifest_json = serde_json::to_value(&manifest)?;
            let manifest_hash = canonical_hash(&manifest_json);
            let sig = signing_key.sign(manifest_hash.as_bytes());
            let proof_sig_hex = hex::encode(sig.to_bytes());

            // Build RemoteSkillPublication without hardcoded endpoint_url
            // Demonstrating dynamic DID resolution by the Trust Gateway!
            let pub_req = RemoteSkillPublication {
                manifest: manifest.clone(),
                provider_did: did.clone(),
                endpoint_url: None, // Auto-resolve via /.well-known/did.json!
                proof_signature: proof_sig_hex,
                capabilities_ucan: None,
                visibility: SkillVisibility::MarketplacePublic,
                publishing_tenant_id: None,
                price_per_call_minor_units: None,
            };

            let publish_url = format!(
                "{}/v1/federation/skills/publish",
                gateway_url.trim_end_matches('/')
            );

            println!(
                "\n[Publisher] Publishing skill '{}' to Trust Gateway at {} ...",
                manifest.name, publish_url
            );
            println!("[Publisher] Provider DID: {}", did);
            println!(
                "[Publisher] Endpoint URL: <omitted - auto-resolve via /.well-known/did.json>"
            );
            println!(
                "[Publisher] Proof Signature: {}...",
                &pub_req.proof_signature[..16]
            );

            let client = reqwest::Client::new();
            let res = client.post(&publish_url).json(&pub_req).send().await?;

            let status = res.status();
            let body = res.text().await?;

            if status.is_success() {
                println!("\n[Publisher] SUCCESS! HTTP {status}");
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                println!("{}", serde_json::to_string_pretty(&parsed)?);
            } else {
                eprintln!("\n[Publisher] FAILED: HTTP {status} - {body}");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
