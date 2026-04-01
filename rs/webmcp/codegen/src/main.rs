use anyhow::{Context, Result};
use clap::Parser;
use ic_webmcp_codegen::{Config, generate_manifest};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Generate WebMCP tool manifests from Internet Computer Candid interfaces.
///
/// Parses a .did file and outputs:
///   - webmcp.json: tool manifest for AI agent discovery
///   - webmcp.js:   browser script for tool registration
#[derive(Parser)]
#[command(name = "ic-webmcp-codegen", version)]
struct Cli {
    /// Path to the Candid .did file
    #[arg(long, short = 'd')]
    did: PathBuf,

    /// Output path for webmcp.json manifest
    #[arg(long, default_value = "webmcp.json")]
    out_manifest: PathBuf,

    /// Output path for webmcp.js registration script
    #[arg(long, default_value = "webmcp.js")]
    out_js: PathBuf,

    /// Canister ID to embed in the manifest
    #[arg(long)]
    canister_id: Option<String>,

    /// Human-readable canister name
    #[arg(long)]
    name: Option<String>,

    /// Description for AI agents
    #[arg(long)]
    description: Option<String>,

    /// Methods to expose (comma-separated). If omitted, all methods are exposed.
    #[arg(long, value_delimiter = ',')]
    expose: Option<Vec<String>>,

    /// Methods that require authentication (comma-separated)
    #[arg(long, value_delimiter = ',')]
    require_auth: Option<Vec<String>>,

    /// Query methods that support certified responses (comma-separated)
    #[arg(long, value_delimiter = ',')]
    certified: Option<Vec<String>>,

    /// Skip generating webmcp.js
    #[arg(long)]
    no_js: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = Config {
        did_file: cli.did,
        canister_id: cli.canister_id,
        name: cli.name,
        description: cli.description,
        expose_methods: cli.expose,
        require_auth: cli.require_auth.unwrap_or_default(),
        certified_queries: cli.certified.unwrap_or_default(),
        method_descriptions: BTreeMap::new(),
        param_descriptions: BTreeMap::new(),
    };

    let manifest = generate_manifest(&config).with_context(|| {
        format!(
            "Failed to generate manifest from {}",
            config.did_file.display()
        )
    })?;

    let json = serde_json::to_string_pretty(&manifest).context("Failed to serialize manifest")?;
    std::fs::write(&cli.out_manifest, &json)
        .with_context(|| format!("Failed to write {}", cli.out_manifest.display()))?;
    eprintln!("Wrote {}", cli.out_manifest.display());

    if !cli.no_js {
        let js = ic_webmcp_codegen::js_emitter::emit_js(&manifest);
        std::fs::write(&cli.out_js, &js)
            .with_context(|| format!("Failed to write {}", cli.out_js.display()))?;
        eprintln!("Wrote {}", cli.out_js.display());
    }

    Ok(())
}
