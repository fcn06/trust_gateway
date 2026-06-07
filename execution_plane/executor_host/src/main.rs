use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod runtime;
mod native_tools;
mod connectors;
mod vp;
mod token_store;
mod jetstream_nonce_store;

#[derive(Parser, Debug)]
#[command(name = "executor_host")]
#[command(about = "Unified Executor Host for the Sovereign Trust Gateway")]
struct Args {
    /// Deployment profile (connector, vp, native-tool)
    #[arg(long, env = "EXECUTOR_PROFILE")]
    profile: String,

    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Path to native tools directory (for native-tool profile)
    #[arg(long, env = "NATIVE_TOOLS_DIR", default_value = "native_tools")]
    native_tools_dir: String,

    /// JWT secret for HMAC fallback (deprecated)
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: Option<String>,

    /// Path to Ed25519 public key for grant verification
    #[arg(long, env = "GRANT_VERIFY_KEY_PATH")]
    grant_verify_key_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,executor_host=debug".into()),
        )
        .init();

    let args = Args::parse();
    tracing::info!("🚀 Unified Executor Host starting [profile={}]", args.profile);

    // 1. Connect to NATS
    let mut nats_options = if let Ok(seed) = std::env::var("NATS_NKEY_SEED") {
        async_nats::ConnectOptions::with_nkey(seed)
    } else {
        async_nats::ConnectOptions::new()
    };
    nats_options = nats_options
        .request_timeout(Some(std::time::Duration::from_secs(30)))
        .retry_on_initial_connect()
        .max_reconnects(60) // Try for up to ~30 minutes with backoff
        .reconnect_delay_callback(|attempts| {
            // Exponential backoff capped at 30 seconds
            let delay = std::cmp::min(2u64.pow(attempts as u32), 30);
            std::time::Duration::from_secs(delay)
        })
        .event_callback(|event| async move {
            match event {
                async_nats::Event::Disconnected => {
                    tracing::error!("🚨 NATS client disconnected!");
                }
                async_nats::Event::Connected => {
                    tracing::info!("✅ NATS client connected");
                }
                async_nats::Event::SlowConsumer(sc) => {
                    tracing::warn!("⚠️ NATS client slow consumer detected on subject: {}", sc);
                }
                _ => {}
            }
        });
    let nats = async_nats::connect_with_options(&args.nats_url, nats_options).await?;
    tracing::info!("✅ Connected to NATS");

    // 2. Build GrantValidator and attach JetStreamNonceStore (JTI replay protection)
    let js = async_nats::jetstream::new(nats.clone());
    let nonce_store = jetstream_nonce_store::JetStreamNonceStore::new(js, "grant_nonces");
    nonce_store.ensure_bucket().await?;

    let grant_validator = build_grant_validator(&args)?;
    let grant_validator = grant_validator.with_nonce_store(Arc::new(nonce_store));
    let grant_validator = Arc::new(grant_validator);

    // 3. Initialize Executor based on profile
    let executor: Arc<dyn trust_core::executor::Executor> = match args.profile.as_str() {
        "native-tool" | "native-skill" => {
            Arc::new(native_tools::NativeToolExecutor::new(&args.native_tools_dir, nats.clone())?)
        }
        #[cfg(feature = "professional")]
        "sandboxed-skill" => {
            Arc::new(host_adapters::skills::executor::SandboxedSkillExecutor::new(&args.native_tools_dir, nats.clone())?)
        }
        "connector" => {
            Arc::new(connectors::ConnectorExecutor::new(nats.clone()).await?)
        }
        "vp" => {
            Arc::new(vp::VpExecutor::new()?)
        }
        _ => anyhow::bail!("Unknown profile: {}", args.profile),
    };

    tracing::info!("✅ Initialized {} executor", executor.name());

    // 4. Start Runtime
    let runtime = runtime::Runtime::new(nats, grant_validator).await?;
    runtime.run(executor, &args.profile).await?;

    Ok(())
}

fn build_grant_validator(args: &Args) -> Result<trust_core::grant_validator::GrantValidator> {
    use trust_core::grant_validator::GrantValidator;

    let mut validator = GrantValidator::new();

    if let Some(ref key_path) = args.grant_verify_key_path {
        let path = std::path::Path::new(key_path);
        if path.is_dir() {
            tracing::info!("🔍 Loading grant verification keys from directory: {:?}", path);
            let mut key_count = 0;
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.is_file() {
                    if let Some(ext) = file_path.extension() {
                        if ext == "pem" || ext == "pub" || ext == "key" {
                            if let Some(filename) = file_path.file_stem() {
                                let kid = filename.to_string_lossy().to_string();
                                let pem = std::fs::read_to_string(&file_path)?;
                                validator = validator.with_ed25519_key(&kid, &pem)?;
                                tracing::info!("✅ Loaded Ed25519 verification key: {} (kid={})", file_path.display(), kid);
                                key_count += 1;
                            }
                        }
                    }
                }
            }
            if key_count == 0 {
                anyhow::bail!("No key files (.pem, .pub, .key) found in directory {:?}", path);
            }
        } else {
            let pem = std::fs::read_to_string(key_path)?;
            let kid = std::env::var("GRANT_SIGNING_KEY_ID").unwrap_or_else(|_| "default".to_string());
            validator = validator.with_ed25519_key(&kid, &pem)?;
            validator = validator.with_fallback_ed25519_key(&pem)?;
            tracing::info!("✅ Loaded single Ed25519 verification key from {:?} (kid={}, fallback enabled)", key_path, kid);
        }
    }

    if let Some(ref secret) = args.jwt_secret {
        validator = validator.with_hmac_key(secret);
        tracing::info!("✅ HMAC grant validation enabled (fallback/legacy)");
    }

    if !validator.has_keys() {
        anyhow::bail!("No grant verification key configured (set GRANT_VERIFY_KEY_PATH or JWT_SECRET)");
    }

    Ok(validator)
}
