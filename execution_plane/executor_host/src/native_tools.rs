use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use trust_core::executor::{Executor, VerifiedGrant};
use trust_core::errors::TrustError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeToolManifest {
    pub name: String,
    pub description: String,
    pub interpreter: String,
    pub script: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LoadedNativeTool {
    pub manifest: NativeToolManifest,
    pub dir: PathBuf,
    pub script_path: PathBuf,
}

pub struct NativeToolExecutor {
    pub tools: HashMap<String, LoadedNativeTool>,
    pub nats: async_nats::Client,
}

impl NativeToolExecutor {
    pub fn new(tools_dir: &str, nats: async_nats::Client) -> Result<Self> {
        let mut tools = HashMap::new();
        let path = Path::new(tools_dir);
        
        if path.exists() && path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let dir = entry.path();
                if dir.is_dir() {
                    let manifest_path = dir.join("manifest.json");
                    if manifest_path.exists() {
                        let content = std::fs::read_to_string(&manifest_path)?;
                        let manifest: NativeToolManifest = serde_json::from_str(&content)?;
                        
                        // Validate interpreter (allow-list)
                        let interpreter_name = Path::new(&manifest.interpreter)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&manifest.interpreter);
                        
                        let allowed = ["bash", "sh", "python3", "python", "node", "deno", "ruby"];
                        if !allowed.contains(&interpreter_name) {
                            tracing::warn!(
                                "⚠️ Skipping native tool '{}': interpreter '{}' is not in the allow-list",
                                manifest.name,
                                manifest.interpreter
                            );
                            continue;
                        }

                        let script_path = dir.join(&manifest.script);
                        
                        // Canonicalize to prevent path traversal
                        match script_path.canonicalize() {
                            Ok(canonical_script) => {
                                match dir.canonicalize() {
                                    Ok(canonical_dir) => {
                                        if !canonical_script.starts_with(&canonical_dir) {
                                            tracing::warn!(
                                                "⚠️ Skipping native tool '{}': path traversal detected in script path '{}'",
                                                manifest.name,
                                                manifest.script
                                            );
                                            continue;
                                        }
                                        tools.insert(manifest.name.clone(), LoadedNativeTool {
                                            manifest,
                                            dir,
                                            script_path: canonical_script,
                                        });
                                    }
                                    Err(e) => {
                                        tracing::warn!("⚠️ Failed to canonicalize directory for tool '{}': {}", manifest.name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("⚠️ Skipping native tool '{}': script file '{}' does not exist or cannot be canonicalized: {}", manifest.name, manifest.script, e);
                            }
                        }
                    }
                }
            }
        }
        
        tracing::info!("✅ Loaded {} native tools from {}", tools.len(), tools_dir);
        Ok(Self { tools, nats })
    }
}

#[async_trait]
impl Executor for NativeToolExecutor {
    fn name(&self) -> &str {
        "native-tool"
    }

    fn handles(&self, tool_id: &str) -> bool {
        self.tools.contains_key(tool_id)
    }

    async fn execute(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let tool_name = grant.allowed_action();
        let tool = self.tools.get(tool_name)
            .ok_or_else(|| TrustError::Internal(format!("Native tool not found: {}", tool_name)))?;

        let manifest = &tool.manifest;
        let timeout = manifest.timeout_seconds
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(30));

        let mut cmd = Command::new(&manifest.interpreter);
        cmd.arg(&tool.script_path);
        cmd.current_dir(&tool.dir);
        cmd.env_clear();

        // Inject environment
        cmd.env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string()));
        cmd.env("HOME", &tool.dir);
        cmd.env("LANG", "C.UTF-8");
        
        // Nomenclature transition support: inject both TOOL_ and SKILL_ variables
        cmd.env("TOOL_ARGS", serde_json::to_string(&args).unwrap_or_default());
        cmd.env("TOOL_NAME", &manifest.name);
        cmd.env("TOOL_ACTION_ID", grant.action_id());
        cmd.env("TOOL_TENANT_ID", grant.tenant_id());

        cmd.env("SKILL_ARGS", serde_json::to_string(&args).unwrap_or_default());
        cmd.env("SKILL_NAME", &manifest.name);
        cmd.env("SKILL_ACTION_ID", grant.action_id());
        cmd.env("SKILL_TENANT_ID", grant.tenant_id());

        for (key, env_var_name) in &manifest.env {
            if let Ok(val) = std::env::var(env_var_name) {
                cmd.env(key, val);
            }
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                let _ = nix::unistd::setsid();
                let mem_limit = 512 * 1024 * 1024; // 512 MB
                let rlimit = nix::libc::rlimit {
                    rlim_cur: mem_limit,
                    rlim_max: mem_limit,
                };
                let _ = nix::libc::setrlimit(nix::libc::RLIMIT_AS, &rlimit);
                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(|e| TrustError::Internal(format!("Failed to spawn native tool: {}", e)))?;
        let pid = child.id().map(|id| nix::unistd::Pid::from_raw(id as i32));
        
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                if !output.status.success() {
                    return Err(TrustError::Internal(format!("Native tool failed (exit {}): {}", output.status, stderr)));
                }

                let json_start = stdout.find('{').unwrap_or(0);
                let json_part = &stdout[json_start..];
                let output_value = serde_json::from_str::<serde_json::Value>(json_part)
                    .unwrap_or_else(|_| serde_json::Value::String(stdout));

                Ok(output_value)
            }
            Ok(Err(e)) => Err(TrustError::Internal(format!("Execution error: {}", e))),
            Err(_) => {
                if let Some(p) = pid {
                    // Send SIGKILL to the process group (since we called setsid)
                    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(-p.as_raw()), nix::sys::signal::Signal::SIGKILL);
                }
                Err(TrustError::Internal("Execution timed out".to_string()))
            }
        }
    }
}
