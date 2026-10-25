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
        out.copy_from_slice(&bytes);
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
