use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ic_webmcp_codegen::{Config, configs_from_dfx_json, generate_manifest, load_canister_ids};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Generate WebMCP tool manifests from Internet Computer Candid interfaces.
#[derive(Parser)]
#[command(name = "ic-webmcp-codegen", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate from a single .did file.
    Did(DidArgs),
    /// Generate from a dfx.json project file (all WebMCP-enabled canisters).
    Dfx(DfxArgs),
}

// ── `did` subcommand ─────────────────────────────────────────────────

/// Generate WebMCP manifests from a single Candid .did file.
#[derive(Parser)]
struct DidArgs {
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

// ── `dfx` subcommand ─────────────────────────────────────────────────

/// Generate WebMCP manifests for all WebMCP-enabled canisters in a dfx.json.
#[derive(Parser)]
struct DfxArgs {
    /// Path to dfx.json (default: ./dfx.json)
    #[arg(long, default_value = "dfx.json")]
    dfx_json: PathBuf,

    /// Path to canister_ids.json for embedding canister principals
    #[arg(long)]
    canister_ids: Option<PathBuf>,

    /// Network name to look up in canister_ids.json (default: ic)
    #[arg(long, default_value = "ic")]
    network: String,

    /// Output directory for generated files (default: .webmcp/)
    #[arg(long, default_value = ".webmcp")]
    out_dir: PathBuf,

    /// Skip generating webmcp.js files
    #[arg(long)]
    no_js: bool,
}

// ── Entry point ───────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Did(args) => run_did(args),
        Command::Dfx(args) => run_dfx(args),
    }
}

fn run_did(args: DidArgs) -> Result<()> {
    let config = Config {
        did_file: args.did,
        canister_id: args.canister_id,
        name: args.name,
        description: args.description,
        expose_methods: args.expose,
        require_auth: args.require_auth.unwrap_or_default(),
        certified_queries: args.certified.unwrap_or_default(),
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
    std::fs::write(&args.out_manifest, &json)
        .with_context(|| format!("Failed to write {}", args.out_manifest.display()))?;
    eprintln!("Wrote {}", args.out_manifest.display());

    if !args.no_js {
        let js = ic_webmcp_codegen::js_emitter::emit_js(&manifest);
        std::fs::write(&args.out_js, &js)
            .with_context(|| format!("Failed to write {}", args.out_js.display()))?;
        eprintln!("Wrote {}", args.out_js.display());
    }

    Ok(())
}

fn run_dfx(args: DfxArgs) -> Result<()> {
    // Load optional canister IDs
    let canister_ids: Option<BTreeMap<String, String>> = match &args.canister_ids {
        Some(path) => Some(
            load_canister_ids(path, &args.network)
                .with_context(|| format!("Failed to load canister IDs from {}", path.display()))?,
        ),
        None => {
            // Try conventional locations automatically
            let candidates = [
                args.dfx_json
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join("canister_ids.json"),
                args.dfx_json
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join(format!(".dfx/{}/canister_ids.json", args.network)),
            ];
            candidates
                .iter()
                .find(|p| p.exists())
                .map(|p| load_canister_ids(p, &args.network))
                .transpose()
                .unwrap_or_default()
        }
    };

    let configs = configs_from_dfx_json(&args.dfx_json, canister_ids.as_ref())
        .with_context(|| format!("Failed to parse {}", args.dfx_json.display()))?;

    if configs.is_empty() {
        eprintln!(
            "No WebMCP-enabled canisters found in {}. Add a `webmcp` section to a canister.",
            args.dfx_json.display()
        );
        return Ok(());
    }

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("Failed to create output dir {}", args.out_dir.display()))?;

    for (canister_name, config) in configs {
        eprintln!("Generating manifest for canister: {}", canister_name);

        let manifest = generate_manifest(&config).with_context(|| {
            format!("Failed to generate manifest for canister {}", canister_name)
        })?;

        let json =
            serde_json::to_string_pretty(&manifest).context("Failed to serialize manifest")?;

        let manifest_path = args.out_dir.join(format!("{}.webmcp.json", canister_name));
        std::fs::write(&manifest_path, &json)
            .with_context(|| format!("Failed to write {}", manifest_path.display()))?;
        eprintln!("  Wrote {}", manifest_path.display());

        if !args.no_js {
            let js = ic_webmcp_codegen::js_emitter::emit_js(&manifest);
            let js_path = args.out_dir.join(format!("{}.webmcp.js", canister_name));
            std::fs::write(&js_path, &js)
                .with_context(|| format!("Failed to write {}", js_path.display()))?;
            eprintln!("  Wrote {}", js_path.display());
        }
    }

    Ok(())
}
