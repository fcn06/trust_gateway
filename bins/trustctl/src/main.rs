use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use std::path::{Path, PathBuf};
use trust_engine::policy::PolicyEngine;
use trust_sdk::manifest::SkillManifest;
use trust_sdk::model::ProposedAction;

#[derive(Parser, Debug)]
#[command(
    name = "trustctl",
    about = "Trust Gateway Control Plane CLI",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Skill {
        #[command(subcommand)]
        action: SkillCommands,
    },
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },
    Tool {
        #[command(subcommand)]
        action: ToolCommands,
    },
    Keys {
        #[command(subcommand)]
        action: KeyCommands,
    },
    Explain {
        trace_id: String,
        #[arg(long, default_value = "audit.db")]
        db_path: PathBuf,
    },
    Onboard {
        #[arg(long)]
        openapi: Option<PathBuf>,
        #[arg(long, default_value = "./onboarding")]
        out_dir: PathBuf,
        #[arg(long, default_value = "external_service")]
        service_name: String,
        #[arg(long, default_value = "did:web:enterprise:partner")]
        author_did: String,
    },
    Contract {
        #[command(subcommand)]
        action: ContractCommands,
    },
    Up {
        #[arg(long, default_value_t = 8080)]
        port: u16,
        #[arg(long, default_value_t = 4015)]
        triage_port: u16,
        #[arg(long, default_value_t = 4010)]
        b2b_port: u16,
        #[arg(long, default_value_t = 8088)]
        swarm_port: u16,
        #[arg(long)]
        check_only: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ContractCommands {
    Sign {
        #[arg(short, long)]
        contract: PathBuf,
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Verify {
        #[arg(short, long)]
        contract: PathBuf,
        #[arg(short, long)]
        key: String,
    },
}

#[derive(Subcommand, Debug)]
enum SkillCommands {
    Init {
        name: String,
        #[arg(short, long, default_value = ".")]
        dir: String,
    },
    Lint {
        path: String,
    },
    Test {
        path: String,
        #[arg(short, long, default_value = "{}")]
        args: String,
    },
    Sign {
        path: String,
        #[arg(short, long)]
        key: String,
    },
    Publish {
        path: String,
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        endpoint: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    Simulate {
        policy: String,
        action: String,
    },
    Sign {
        policy: String,
        #[arg(short, long)]
        key: String,
    },
}

#[derive(Subcommand, Debug)]
enum ToolCommands {
    List {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        endpoint: String,
    },
    Run {
        name: String,
        #[arg(short, long, default_value = "{}")]
        args: String,
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        endpoint: String,
    },
}

#[derive(Subcommand, Debug)]
enum KeyCommands {
    Gen {
        #[arg(short, long, default_value = "grant_signing.pem")]
        out: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = run_command(cli.command).await;
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_command(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Skill { action } => match action {
            SkillCommands::Init { name, dir } => {
                let target = Path::new(&dir).join(&name);
                std::fs::create_dir_all(&target)?;
                let manifest = serde_json::json!({
                    "schema_version": "lianxi.skill/v1",
                    "id": format!("io.lianxi.skill.{}@v1", name),
                    "name": name,
                    "version": "1.0.0",
                    "description": format!("Skill {}", name),
                    "author_did": "did:web:lianxi.io",
                    "data_origin_trust": "TrustedInternal",
                    "lineage_rules": [],
                    "execution": {
                        "runtime": "native_tool",
                        "entrypoint": "run.sh",
                        "timeout_secs": 30,
                        "memory_limit_mb": 512,
                        "allowed_interpreters": ["bash", "sh"]
                    },
                    "input_schema": { "type": "object" },
                    "policy_defaults": {
                        "default_tier": "tier0_auto",
                        "max_frequency_per_trace": 3,
                        "default_risk_level": "low",
                        "operation_kind": "read"
                    },
                    "egress": {
                        "contains_pii": false,
                        "max_payload_bytes": 65536,
                        "allowed_fields": []
                    }
                });
                std::fs::write(
                    target.join("manifest.json"),
                    serde_json::to_string_pretty(&manifest)?,
                )?;
                std::fs::write(
                    target.join("run.sh"),
                    "#!/usr/bin/env bash\necho '{\"result\":\"ok\"}'\n",
                )?;
                println!("Initialized skill template at {}", target.display());
            }
            SkillCommands::Lint { path } => {
                let manifest_path = if Path::new(&path).is_dir() {
                    Path::new(&path).join("manifest.json")
                } else {
                    PathBuf::from(path)
                };
                let content = std::fs::read_to_string(&manifest_path)?;
                let manifest: SkillManifest = serde_json::from_str(&content)?;
                manifest.validate()?;
                println!("Skill manifest is VALID: {}", manifest.id);
            }
            SkillCommands::Test { path, args } => {
                let manifest_path = if Path::new(&path).is_dir() {
                    Path::new(&path).join("manifest.json")
                } else {
                    PathBuf::from(&path)
                };
                let content = std::fs::read_to_string(&manifest_path)?;
                let manifest: SkillManifest = serde_json::from_str(&content)?;
                manifest.validate()?;

                let skill_dir = manifest_path.parent().unwrap();
                let script = skill_dir.join(&manifest.execution.entrypoint);
                let parsed_args: serde_json::Value = serde_json::from_str(&args)?;

                let mut cmd = std::process::Command::new("bash");
                cmd.arg(&script);
                cmd.current_dir(skill_dir);
                cmd.env("TOOL_ARGS", serde_json::to_string(&parsed_args)?);
                cmd.env("TOOL_NAME", &manifest.name);
                let out = cmd.output()?;
                println!("Status: {}", out.status);
                println!("Stdout: {}", String::from_utf8_lossy(&out.stdout));
            }
            SkillCommands::Sign { path, key } => {
                let manifest_path = if Path::new(&path).is_dir() {
                    Path::new(&path).join("manifest.json")
                } else {
                    PathBuf::from(&path)
                };
                let content = std::fs::read_to_string(&manifest_path)?;
                let key_pem = std::fs::read_to_string(&key)?;
                // Strip PEM headers to obtain raw 32 bytes or parse key
                let raw_seed = parse_pem_or_hex_key(&key_pem)?;
                let signing_key = SigningKey::from_bytes(&raw_seed);
                let signature = signing_key.sign(content.as_bytes());
                let sig_hex = hex::encode(signature.to_bytes());
                let sig_file = manifest_path.parent().unwrap().join("manifest.json.sig");
                std::fs::write(&sig_file, sig_hex)?;
                println!("Wrote detached signature to {}", sig_file.display());
            }
            SkillCommands::Publish { path, endpoint } => {
                let manifest_path = if Path::new(&path).is_dir() {
                    Path::new(&path).join("manifest.json")
                } else {
                    PathBuf::from(&path)
                };
                let content = std::fs::read_to_string(&manifest_path)?;
                let manifest: SkillManifest = serde_json::from_str(&content)?;
                manifest.validate()?;

                let url = format!(
                    "{}/v1/federation/skills/publish",
                    endpoint.trim_end_matches('/')
                );
                let client = reqwest::Client::new();
                let res = client.post(&url).json(&manifest).send().await?;
                let status = res.status();
                if status == reqwest::StatusCode::NOT_IMPLEMENTED {
                    let body = res.text().await?;
                    println!("Response {}: {}", status, body);
                    println!("Federation publication requires Pro edition.");
                } else {
                    println!("Response: {}", status);
                }
            }
        },
        Commands::Policy { action } => match action {
            PolicyCommands::Simulate { policy, action } => {
                let p_content = std::fs::read_to_string(&policy)?;
                let engine = PolicyEngine::from_toml(&p_content)?;
                let a_content = std::fs::read_to_string(&action)?;
                let proposed: ProposedAction = serde_json::from_str(&a_content)?;
                println!("Policy loaded. Fingerprint: {}", engine.fingerprint());
                println!("Simulation completed for action {}", proposed.action_id);
            }
            PolicyCommands::Sign { policy, key } => {
                let content = std::fs::read_to_string(&policy)?;
                let key_pem = std::fs::read_to_string(&key)?;
                let raw_seed = parse_pem_or_hex_key(&key_pem)?;
                let signing_key = SigningKey::from_bytes(&raw_seed);
                let signature = signing_key.sign(content.as_bytes());
                let sig_hex = hex::encode(signature.to_bytes());
                let sig_file = format!("{policy}.sig");
                std::fs::write(&sig_file, sig_hex)?;
                println!("Wrote policy signature to {sig_file}");
            }
        },
        Commands::Tool { action } => match action {
            ToolCommands::List { endpoint } => {
                let url = format!("{}/v1/tools/registry", endpoint.trim_end_matches('/'));
                let client = reqwest::Client::new();
                let res = client
                    .get(&url)
                    .send()
                    .await?
                    .json::<serde_json::Value>()
                    .await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            ToolCommands::Run {
                name,
                args,
                endpoint,
            } => {
                let parsed_args: serde_json::Value = serde_json::from_str(&args)?;
                let action = ProposedAction {
                    action_id: format!("act_{}", uuid::Uuid::new_v4()),
                    tool_name: name,
                    arguments: parsed_args,
                    tenant_id: "default".to_string(),
                    workspace_id: "default".to_string(),
                    ..Default::default()
                };
                let url = format!("{}/v1/actions/propose", endpoint.trim_end_matches('/'));
                let client = reqwest::Client::new();
                let api_key = std::env::var("TRUST_GATEWAY_API_KEY")
                    .unwrap_or_else(|_| "sk_default_dev_key".to_string());
                let res = client
                    .post(&url)
                    .header("Authorization", format!("Bearer {api_key}"))
                    .json(&action)
                    .send()
                    .await?;
                println!("Status: {}", res.status());
                println!("{}", res.text().await?);
            }
        },
        Commands::Keys { action } => match action {
            KeyCommands::Gen { out } => {
                let key_pair = jwt_simple::prelude::Ed25519KeyPair::generate();
                let pem = key_pair.to_pem();
                std::fs::write(&out, pem)?;
                println!("Generated Ed25519 private key at {out}");
            }
        },
        Commands::Explain { trace_id, db_path } => {
            if !db_path.exists() {
                anyhow::bail!("Audit database not found at {}", db_path.display());
            }
            let sink = trust_engine::local_adapters::sqlite_audit::SqliteAuditSink::from_file(&db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open audit database: {e}"))?;
            let events = sink
                .get_events_by_trace(&trace_id)
                .map_err(|e| anyhow::anyhow!("Failed to query audit trail: {e}"))?;

            if events.is_empty() {
                println!("No audit records found for trace_id: {trace_id}");
                return Ok(());
            }

            println!("================================================================================");
            println!(" 🔍 Trust Trace Explanation: {trace_id}");
            println!(" Total Records: {}", events.len());
            println!("================================================================================");

            for (idx, ev) in events.iter().enumerate() {
                let dt = chrono::DateTime::from_timestamp(ev.timestamp, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| ev.timestamp.to_string());
                println!("[Step {}] {} | Event: {}", idx + 1, dt, ev.event_type);
                println!("  Tenant:   {}", ev.tenant_id);
                if let Some(ref act) = ev.action_id {
                    println!("  Action:   {}", act);
                }
                println!("  Details:  {}", serde_json::to_string_pretty(&ev.details)?);
                println!("--------------------------------------------------------------------------------");
            }
        }
        Commands::Onboard {
            openapi,
            out_dir,
            service_name,
            author_did,
        } => {
            let path = openapi.ok_or_else(|| {
                anyhow::anyhow!(
                    "--openapi <FILE> is required (sample: examples/inputs/openapi/stripe_billing_openapi.json)"
                )
            })?;
            if !path.exists() {
                anyhow::bail!("OpenAPI specification not found at {}", path.display());
            }
            let raw = std::fs::read_to_string(&path)?;
            let spec_label = path.display().to_string();

            let inspector = trust_inspect::openapi::OpenApiInspector::default();
            let ops = inspector
                .inspect_spec_str(&raw)
                .map_err(|e| anyhow::anyhow!("Failed to inspect OpenAPI: {e}"))?;

            std::fs::create_dir_all(&out_dir)?;

            // 1. Generate Manifests directory
            let manifests_dir = out_dir.join("skills");
            std::fs::create_dir_all(&manifests_dir)?;
            for op in &ops {
                let manifest = trust_inspect::synthesizer::ArtifactSynthesizer::generate_manifest(
                    op,
                    &service_name,
                    &author_did,
                );
                let manifest_path = manifests_dir.join(format!("{}.json", op.operation_id));
                std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
            }

            // 2. Generate Policy Draft
            let policy_draft = trust_inspect::synthesizer::ArtifactSynthesizer::generate_policy_draft(
                &ops,
                &service_name,
            );
            let policy_path = out_dir.join("policy.draft.toml");
            std::fs::write(&policy_path, policy_draft)?;

            // 3. Generate Onboarding Report
            let report = trust_inspect::synthesizer::ArtifactSynthesizer::generate_onboarding_report(
                &ops,
                &service_name,
                &spec_label,
            );
            let report_path = out_dir.join("onboarding-report.md");
            std::fs::write(&report_path, report)?;

            println!("================================================================================");
            println!(" 🛡️ Governed Onboarding Dossier Synthesized for '{service_name}'");
            println!(" Total Endpoints Inspected: {}", ops.len());
            println!(" Artifacts Written to:      {}", out_dir.display());
            println!("   - Manifests Directory:   {}", manifests_dir.display());
            println!("   - Policy Draft:          {}", policy_path.display());
            println!("   - Onboarding Dossier:    {}", report_path.display());
            println!("================================================================================");
        }
        Commands::Up {
            port,
            triage_port,
            b2b_port,
            swarm_port,
            check_only,
        } => {
            println!("================================================================================");
            println!(" 🌐 Checking Governed Agentic Stack Health & Mesh Topology");
            println!("================================================================================");
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(1500))
                .build()?;

            let services: [(&str, u16, &[&str]); 5] = [
                ("Tier 1 Swarm Gateway", swarm_port, &["/healthz", "/health"]),
                ("Tier 2 Trust Gateway", port, &["/healthz", "/health"]),
                ("Tier 2 Policy Plane (Triage)", triage_port, &["/healthz", "/health"]),
                ("Tier 3 Commercial B2B Agent", b2b_port, &["/healthz", "/health", "/agent-card"]),
                ("Tier 3 Mapping Agent", 4020, &["/healthz", "/health"]),
            ];

            let mut all_online = true;
            for (name, p, candidate_paths) in services {
                let mut service_status = "⚪ OFFLINE (Unreachable)";
                let mut ok = false;
                for path in candidate_paths {
                    let url = format!("http://127.0.0.1:{p}{path}");
                    if let Ok(resp) = client.get(&url).send().await {
                        if resp.status().is_success() {
                            service_status = "🟢 ONLINE (200 OK)";
                            ok = true;
                            break;
                        } else {
                            service_status = "🟡 UNHEALTHY";
                        }
                    }
                }
                if !ok {
                    all_online = false;
                }
                println!("  * {:<32} : {:<6} -> {}", name, p, service_status);
            }
            println!("================================================================================");

            if check_only {
                if all_online {
                    println!("All mesh services are healthy and responding.");
                } else {
                    println!("One or more mesh services are offline or unhealthy.");
                }
                return Ok(());
            }

            if all_online {
                println!("🚀 All stack tiers are operational. Ready to accept agent requests.");
            } else {
                println!("ℹ️ Stack startup guidance:");
                println!("   Start the full stack from the repository root with: make run");
                println!("   Then inspect it with: make status");
            }
        }
        Commands::Contract { action } => match action {
            ContractCommands::Sign { contract, key, out } => {
                let raw = std::fs::read_to_string(&contract)?;
                let mut c: trust_sdk::contracts::SignedContract = serde_json::from_str(&raw)?;
                let key_str = if std::path::Path::new(&key).exists() {
                    std::fs::read_to_string(&key)?
                } else {
                    key
                };
                let key_bytes = parse_pem_or_hex_key(&key_str)?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                c.sign(&signing_key)
                    .map_err(|e| anyhow::anyhow!("Contract signing failed: {e}"))?;

                let out_path = out.unwrap_or(contract);
                std::fs::write(&out_path, serde_json::to_string_pretty(&c)?)?;
                println!("Successfully signed contract '{}'. Output: {}", c.contract_id, out_path.display());
            }
            ContractCommands::Verify { contract, key } => {
                let raw = std::fs::read_to_string(&contract)?;
                let c: trust_sdk::contracts::SignedContract = serde_json::from_str(&raw)?;
                let key_str = if std::path::Path::new(&key).exists() {
                    std::fs::read_to_string(&key)?
                } else {
                    key
                };
                let key_bytes = parse_pem_or_hex_key(&key_str)?;
                let verifying_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes).verifying_key();
                c.verify(&verifying_key)
                    .map_err(|e| anyhow::anyhow!("Contract verification failed: {e}"))?;
                println!("Contract '{}' signature is VALID.", c.contract_id);
            }
        },
    }
    Ok(())
}

fn parse_pem_or_hex_key(key_str: &str) -> anyhow::Result<[u8; 32]> {
    let clean = key_str.trim();
    if clean.contains("BEGIN PRIVATE KEY") {
        let pair = jwt_simple::prelude::Ed25519KeyPair::from_pem(clean)
            .map_err(|e| anyhow::anyhow!("PEM decode failed: {e}"))?;
        let bytes = pair.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        return Ok(out);
    }
    let bytes = hex::decode(clean).map_err(|e| anyhow::anyhow!("Hex decode failed: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("Key bytes must be exactly 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_engine::traits::AuditSink;
    use trust_sdk::model::AuditEvent;

    #[tokio::test]
    async fn test_explain_command() {
        let temp_dir = std::env::temp_dir();
        let db_file = temp_dir.join(format!("test_audit_{}.db", uuid::Uuid::new_v4()));

        let sink = trust_engine::local_adapters::sqlite_audit::SqliteAuditSink::from_file(&db_file).unwrap();
        let ev = AuditEvent {
            event_id: "evt_123".to_string(),
            timestamp: 1730000000,
            event_type: "policy_evaluation".to_string(),
            tenant_id: "tenant-default".to_string(),
            trace_id: "trace-xyz-999".to_string(),
            action_id: Some("act_1".to_string()),
            details: serde_json::json!({"decision": "allow", "tier": "tier0_auto"}),
            prev_hash: Some("0000000000000000000000000000000000000000000000000000000000000000".to_string()),
            hash: Some("dummyhash".to_string()),
        };
        sink.append(ev).await.unwrap();

        let cmd = Commands::Explain {
            trace_id: "trace-xyz-999".to_string(),
            db_path: db_file.clone(),
        };

        let res = run_command(cmd).await;
        assert!(res.is_ok());

        let _ = std::fs::remove_file(db_file);
    }

    #[tokio::test]
    async fn test_onboard_command() {
        let temp_dir = std::env::temp_dir();
        let spec_file = temp_dir.join(format!("spec_{}.json", uuid::Uuid::new_v4()));
        let out_dir = temp_dir.join(format!("out_{}", uuid::Uuid::new_v4()));

        let spec_content = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test Service", "version": "1.0.0" },
            "paths": {
                "/test/query": {
                    "get": {
                        "operationId": "get_test_query",
                        "responses": { "200": { "description": "OK" } }
                    }
                },
                "/test/drop": {
                    "delete": {
                        "operationId": "drop_test_data",
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#;
        std::fs::write(&spec_file, spec_content).unwrap();

        let cmd = Commands::Onboard {
            openapi: Some(spec_file.clone()),
            out_dir: out_dir.clone(),
            service_name: "test_service".to_string(),
            author_did: "did:web:example.com".to_string(),
        };

        let res = run_command(cmd).await;
        assert!(res.is_ok());

        assert!(out_dir.join("policy.draft.toml").exists());
        assert!(out_dir.join("onboarding-report.md").exists());
        assert!(out_dir.join("skills/get_test_query.json").exists());
        assert!(out_dir.join("skills/drop_test_data.json").exists());

        let policy_str = std::fs::read_to_string(out_dir.join("policy.draft.toml")).unwrap();
        assert!(policy_str.contains("action = \"deny\""));
        assert!(policy_str.contains("action = \"allow\""));

        let _ = std::fs::remove_file(spec_file);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[tokio::test]
    async fn test_onboard_demo_command() {
        let temp_dir = std::env::temp_dir();
        let out_dir = temp_dir.join(format!("out_demo_{}", uuid::Uuid::new_v4()));

        let cmd = Commands::Onboard {
            openapi: Some(std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../examples/inputs/openapi/stripe_billing_openapi.json"))),
            out_dir: out_dir.clone(),
            service_name: "stripe_billing_demo".to_string(),
            author_did: "did:web:stripe.com".to_string(),
        };

        let res = run_command(cmd).await;
        assert!(res.is_ok());

        assert!(out_dir.join("policy.draft.toml").exists());
        assert!(out_dir.join("onboarding-report.md").exists());
        assert!(out_dir.join("skills/create_charge.json").exists());
        assert!(out_dir.join("skills/purge_account_data.json").exists());

        let report_str = std::fs::read_to_string(out_dir.join("onboarding-report.md")).unwrap();
        assert!(report_str.contains("purge_account_data"));

        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[tokio::test]
    async fn test_up_check_only_command() {
        let cmd = Commands::Up {
            port: 8080,
            triage_port: 4015,
            b2b_port: 4010,
            swarm_port: 8088,
            check_only: true,
        };
        let res = run_command(cmd).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_contract_sign_and_verify_command() {
        let temp_dir = std::env::temp_dir();
        let contract_file = temp_dir.join(format!("contract_{}.json", uuid::Uuid::new_v4()));

        let key_pair = jwt_simple::prelude::Ed25519KeyPair::generate();
        let key_pem = key_pair.to_pem();

        let contract_content = r#"{
            "contract_id": "contract_weather_cli_test",
            "version": "1.0.0",
            "skill_id": "claw_weather",
            "author_did": "did:web:weather.com",
            "schema_hash": "sha256_dummy_hash",
            "created_at": 1730000000,
            "expires_at": 1799999999,
            "signature": ""
        }"#;
        std::fs::write(&contract_file, contract_content).unwrap();

        // 1. Sign contract
        let sign_cmd = Commands::Contract {
            action: ContractCommands::Sign {
                contract: contract_file.clone(),
                key: key_pem.clone(),
                out: None,
            },
        };
        assert!(run_command(sign_cmd).await.is_ok());

        // 2. Verify contract
        let verify_cmd = Commands::Contract {
            action: ContractCommands::Verify {
                contract: contract_file.clone(),
                key: key_pem,
            },
        };
        assert!(run_command(verify_cmd).await.is_ok());

        let _ = std::fs::remove_file(contract_file);
    }
}
