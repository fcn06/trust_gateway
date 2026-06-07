// ─────────────────────────────────────────────────────────────
// Native Tool Registry — scans /native_tools/*/manifest.json
//
// Each native tool directory contains:
//   manifest.json   — tool metadata (name, description, args, script)
//   run.sh / run.py — the actual script to execute
//   README.md       — (optional) rich tool documentation
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A native tool loaded from its manifest.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeToolManifest {
    pub name: String,
    pub description: String,
    /// The script to run, relative to the tool directory.
    pub script: String,
    /// Interpreter to use (e.g. "bash", "python3"). Defaults to "bash".
    #[serde(default = "default_interpreter")]
    pub interpreter: String,
    /// Input arguments schema (JSON Schema).
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// Environment variables to inject (key → env var name).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Tags for policy matching.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Maximum execution time in seconds (overrides global default).
    pub timeout_seconds: Option<u64>,

    // ── Extended fields (skills.md philosophy mapped to native tools) ──────────────
    /// Tool category (e.g. "utility", "operations", "diagnostics").
    #[serde(default)]
    pub category: Option<String>,
    /// Hint for the LLM: "native" means prefer this over external alternatives.
    #[serde(default)]
    pub priority_hint: Option<String>,
    /// "atomic" (single call) or "multi_step" (requires read-then-execute).
    #[serde(default)]
    pub procedure_type: Option<String>,
    /// Optional cron schedule string (e.g. "0 9 * * 1").
    #[serde(default)]
    pub cron: Option<String>,
}

fn default_interpreter() -> String {
    "bash".to_string()
}

/// In-memory native tool registry (thread-safe for hot-reload).
pub struct NativeToolRegistry {
    tools: std::sync::RwLock<HashMap<String, LoadedNativeTool>>,
    tools_dir: PathBuf,
}

/// A native tool with its resolved filesystem paths.
#[derive(Debug, Clone)]
pub struct LoadedNativeTool {
    pub manifest: NativeToolManifest,
    /// Absolute path to the tool directory.
    pub dir: PathBuf,
    /// Absolute path to the script file.
    pub script_path: PathBuf,
}

/// Public-facing native tool info for the GET /skills (now /tools or similar) endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeToolInfo {
    pub name: String,
    pub description: String,
    pub interpreter: String,
    pub tags: Vec<String>,
    pub input_schema: serde_json::Value,
    /// Tool category (e.g. "utility", "operations").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Whether rich documentation (README.md) is available.
    #[serde(default)]
    pub documentation_available: bool,
    /// "atomic" or "multi_step".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procedure_type: Option<String>,
    /// "native" priority hint for LLM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_hint: Option<String>,
    /// Optional cron schedule string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
}

/// Documentation response for the `GET /skills/{name}/docs` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeToolDocs {
    pub name: String,
    pub description: String,
    /// Full markdown documentation content (from README.md/SKILL.md/TOOL.md).
    pub documentation: Option<String>,
    pub input_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procedure_type: Option<String>,
}

impl NativeToolRegistry {
    /// Scan a directory for native tool manifests.
    ///
    /// Expects the structure:
    /// ```
    /// native_tools/
    ///   my_tool/
    ///     manifest.json
    ///     run.sh
    ///     README.md       (optional)
    ///   another_tool/
    ///     manifest.json
    ///     run.py
    /// ```
    pub fn scan(tools_dir: &str) -> Result<Self> {
        let dir = Path::new(tools_dir);
        let tools = Self::scan_dir(dir)?;
        Ok(Self {
            tools: std::sync::RwLock::new(tools),
            tools_dir: dir.to_path_buf(),
        })
    }

    /// Internal: scan a directory and return a map of loaded native tools.
    fn scan_dir(dir: &Path) -> Result<HashMap<String, LoadedNativeTool>> {
        let mut tools = HashMap::new();

        if !dir.exists() {
            tracing::warn!(
                "⚠️ Native tools directory '{}' does not exist — no tools loaded",
                dir.display()
            );
            return Ok(tools);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let tool_dir = entry.path();
            let manifest_path = tool_dir.join("manifest.json");

            if !manifest_path.exists() {
                tracing::debug!("Skipping {}: no manifest.json", tool_dir.display());
                continue;
            }

            match Self::load_tool(&tool_dir, &manifest_path) {
                Ok(loaded) => {
                    tracing::info!(
                        "   🦞 Loaded native tool '{}' from {}",
                        loaded.manifest.name,
                        tool_dir.display()
                    );
                    tools.insert(loaded.manifest.name.clone(), loaded);
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to load native tool from {}: {}",
                        tool_dir.display(),
                        e
                    );
                }
            }
        }

        Ok(tools)
    }

    fn load_tool(tool_dir: &Path, manifest_path: &Path) -> Result<LoadedNativeTool> {
        let contents = std::fs::read_to_string(manifest_path)?;
        let manifest: NativeToolManifest = serde_json::from_str(&contents)?;

        // ── Security: Interpreter allow-list ────────────────────
        // Only allow known safe interpreters. This prevents malicious
        // manifests from running arbitrary binaries.
        const ALLOWED_INTERPRETERS: &[&str] =
            &["bash", "sh", "python3", "python", "node", "deno", "ruby"];
        if !ALLOWED_INTERPRETERS.contains(&manifest.interpreter.as_str()) {
            anyhow::bail!(
                "Interpreter '{}' is not in the allow-list {:?}",
                manifest.interpreter,
                ALLOWED_INTERPRETERS
            );
        }

        let script_path = tool_dir.join(&manifest.script);
        if !script_path.exists() {
            anyhow::bail!(
                "Script '{}' not found in {}",
                manifest.script,
                tool_dir.display()
            );
        }

        // ── Security: Path traversal prevention ─────────────────
        // Canonicalize both paths and verify the script stays within
        // the tool directory. Prevents manifest.script = "../../etc/passwd".
        let canonical_script = script_path.canonicalize()?;
        let canonical_dir = tool_dir.canonicalize()?;
        if !canonical_script.starts_with(&canonical_dir) {
            anyhow::bail!(
                "Script path '{}' escapes tool directory '{}' — possible path traversal",
                canonical_script.display(),
                canonical_dir.display()
            );
        }

        Ok(LoadedNativeTool {
            manifest,
            dir: tool_dir.to_path_buf(),
            script_path: canonical_script,
        })
    }

    /// Get a loaded native tool by name (returns a clone for thread safety).
    pub fn get(&self, name: &str) -> Option<LoadedNativeTool> {
        self.tools.read().unwrap().get(name).cloned()
    }

    /// Number of loaded native tools.
    pub fn count(&self) -> usize {
        self.tools.read().unwrap().len()
    }

    /// List all loaded native tools (public info only).
    pub fn list(&self) -> Vec<NativeToolInfo> {
        self.tools
            .read()
            .unwrap()
            .values()
            .map(|s| {
                let has_docs = s.dir.join("README.md").exists()
                    || s.dir.join("SKILL.md").exists()
                    || s.dir.join("docs.md").exists()
                    || s.dir.join("TOOL.md").exists();
                NativeToolInfo {
                    name: s.manifest.name.clone(),
                    description: s.manifest.description.clone(),
                    interpreter: s.manifest.interpreter.clone(),
                    tags: s.manifest.tags.clone(),
                    input_schema: s.manifest.input_schema.clone(),
                    category: s.manifest.category.clone(),
                    documentation_available: has_docs,
                    procedure_type: s.manifest.procedure_type.clone(),
                    priority_hint: s.manifest.priority_hint.clone(),
                    cron: s.manifest.cron.clone(),
                }
            })
            .collect()
    }

    /// Get the full documentation for a native tool.
    ///
    /// Reads README.md, SKILL.md, TOOL.md, or docs.md from the tool directory.
    /// Returns None if the tool doesn't exist.
    pub fn get_docs(&self, name: &str) -> Option<NativeToolDocs> {
        let tools = self.tools.read().unwrap();
        let tool = tools.get(name)?;

        // Try README.md, TOOL.md, SKILL.md, docs.md in order of preference
        let docs_content = ["README.md", "TOOL.md", "SKILL.md", "docs.md"]
            .iter()
            .find_map(|filename| {
                let path = tool.dir.join(filename);
                std::fs::read_to_string(&path).ok()
            });

        Some(NativeToolDocs {
            name: tool.manifest.name.clone(),
            description: tool.manifest.description.clone(),
            documentation: docs_content,
            input_schema: tool.manifest.input_schema.clone(),
            category: tool.manifest.category.clone(),
            tags: tool.manifest.tags.clone(),
            procedure_type: tool.manifest.procedure_type.clone(),
        })
    }

    /// Rescan the native tools directory for new or updated tools.
    ///
    /// Returns the names of newly discovered tools (not previously loaded).
    /// Existing tools are also refreshed with updated manifests.
    pub fn rescan(&self) -> Vec<String> {
        match Self::scan_dir(&self.tools_dir) {
            Ok(new_tools) => {
                let mut current = self.tools.write().unwrap();
                let new_names: Vec<String> = new_tools
                    .keys()
                    .filter(|k| !current.contains_key(*k))
                    .cloned()
                    .collect();
                let total = new_tools.len();
                *current = new_tools;
                if !new_names.is_empty() {
                    tracing::info!(
                        "🔄 Rescan found {} new native tools: {:?} (total: {})",
                        new_names.len(),
                        new_names,
                        total
                    );
                }
                new_names
            }
            Err(e) => {
                tracing::error!("❌ Native tool rescan failed: {}", e);
                vec![]
            }
        }
    }

    /// Return the path to the native tools directory.
    pub fn tools_dir(&self) -> &Path {
        &self.tools_dir
    }
}
