//! Parse the `webmcp` configuration section from `dfx.json`.
//!
//! This module reads the standard `dfx.json` project file and extracts
//! a `Config` for each canister that has a `webmcp` block, allowing
//! manifest generation to be driven entirely from `dfx.json`.
//!
//! ## Expected `dfx.json` shape
//!
//! ```json
//! {
//!   "canisters": {
//!     "backend": {
//!       "type": "rust",
//!       "candid": "backend.did",
//!       "webmcp": {
//!         "enabled": true,
//!         "name": "My DApp",
//!         "description": "Description for AI agents",
//!         "expose_methods": ["get_items", "checkout"],
//!         "require_auth": ["checkout"],
//!         "certified_queries": ["get_items"],
//!         "descriptions": {
//!           "get_items": "List available products",
//!           "checkout": "Complete purchase"
//!         },
//!         "param_descriptions": {
//!           "checkout.payment_method": "Payment method: icp or cycles"
//!         }
//!       }
//!     }
//!   }
//! }
//! ```

use crate::config::Config;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── dfx.json schema ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DfxJson {
    canisters: Option<BTreeMap<String, DfxCanister>>,
}

#[derive(Debug, Deserialize)]
struct DfxCanister {
    /// Path to the .did file (relative to dfx.json)
    candid: Option<String>,
    /// WebMCP configuration block
    webmcp: Option<DfxWebMCPConfig>,
}

/// The `webmcp` section inside a canister definition in `dfx.json`.
#[derive(Debug, Deserialize, Default)]
pub struct DfxWebMCPConfig {
    /// Whether WebMCP generation is enabled for this canister. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Human-readable name for the canister (shown to agents)
    pub name: Option<String>,

    /// Description for AI agents
    pub description: Option<String>,

    /// Which methods to expose. If absent, all service methods are exposed.
    pub expose_methods: Option<Vec<String>>,

    /// Methods that require authentication
    #[serde(default)]
    pub require_auth: Vec<String>,

    /// Query methods that support certified responses
    #[serde(default)]
    pub certified_queries: Vec<String>,

    /// Human-readable descriptions per method
    #[serde(default)]
    pub descriptions: BTreeMap<String, String>,

    /// Descriptions per parameter (format: "method.param_name")
    #[serde(default)]
    pub param_descriptions: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

// ── Public API ───────────────────────────────────────────────────────

/// Parse `dfx.json` and return one `Config` per WebMCP-enabled canister.
///
/// The `canister_ids` map is optional — if provided it is used to embed
/// canister IDs into the generated manifests. The keys are canister names,
/// the values are principal text strings (as found in `.dfx/local/canister_ids.json`
/// or `canister_ids.json`).
pub fn configs_from_dfx_json(
    dfx_json_path: &Path,
    canister_ids: Option<&BTreeMap<String, String>>,
) -> Result<Vec<(String, Config)>> {
    let content = std::fs::read_to_string(dfx_json_path)
        .with_context(|| format!("Failed to read {}", dfx_json_path.display()))?;

    let dfx: DfxJson = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", dfx_json_path.display()))?;

    let dfx_dir = dfx_json_path.parent().unwrap_or_else(|| Path::new("."));

    let mut results = Vec::new();

    for (canister_name, canister) in dfx.canisters.unwrap_or_default() {
        let Some(webmcp) = canister.webmcp else {
            continue;
        };
        if !webmcp.enabled {
            continue;
        }

        let candid_rel = canister.candid.as_deref().unwrap_or("canister.did");
        let did_file = resolve_path(dfx_dir, candid_rel);

        let canister_id = canister_ids
            .and_then(|ids| ids.get(&canister_name))
            .cloned();

        let config = Config {
            did_file,
            canister_id,
            name: webmcp.name.or_else(|| Some(canister_name.clone())),
            description: webmcp.description,
            expose_methods: webmcp.expose_methods,
            require_auth: webmcp.require_auth,
            certified_queries: webmcp.certified_queries,
            method_descriptions: webmcp.descriptions,
            param_descriptions: webmcp.param_descriptions,
        };

        results.push((canister_name, config));
    }

    Ok(results)
}

/// Parse a `canister_ids.json` file (as produced by `dfx deploy`) into a name→principal map.
///
/// Supports both the root-level `canister_ids.json` and `.dfx/<network>/canister_ids.json`.
/// The file format is: `{ "canister_name": { "ic": "principal", "local": "principal" } }`.
pub fn load_canister_ids(path: &Path, network: &str) -> Result<BTreeMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let raw: BTreeMap<String, BTreeMap<String, String>> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let ids = raw
        .into_iter()
        .filter_map(|(name, nets)| nets.get(network).map(|id| (name, id.clone())))
        .collect();

    Ok(ids)
}

fn resolve_path(base: &Path, relative: &str) -> PathBuf {
    let p = Path::new(relative);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_json(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_parse_basic_dfx_json() {
        let f = write_temp_json(
            r#"{
              "canisters": {
                "backend": {
                  "type": "rust",
                  "candid": "backend.did",
                  "webmcp": {
                    "name": "My App",
                    "description": "Test app",
                    "expose_methods": ["greet", "transfer"],
                    "require_auth": ["transfer"],
                    "certified_queries": ["greet"],
                    "descriptions": {
                      "greet": "Say hello",
                      "transfer": "Send tokens"
                    }
                  }
                }
              }
            }"#,
        );

        let configs = configs_from_dfx_json(f.path(), None).unwrap();
        assert_eq!(configs.len(), 1);

        let (name, config) = &configs[0];
        assert_eq!(name, "backend");
        assert_eq!(config.name.as_deref(), Some("My App"));
        assert_eq!(config.description.as_deref(), Some("Test app"));
        assert_eq!(
            config.expose_methods.as_deref(),
            Some(["greet".to_string(), "transfer".to_string()].as_slice())
        );
        assert_eq!(config.require_auth, ["transfer"]);
        assert_eq!(config.certified_queries, ["greet"]);
        assert_eq!(config.method_descriptions["greet"], "Say hello");
    }

    #[test]
    fn test_skips_disabled_canister() {
        let f = write_temp_json(
            r#"{
              "canisters": {
                "backend": {
                  "candid": "backend.did",
                  "webmcp": { "enabled": false }
                }
              }
            }"#,
        );

        let configs = configs_from_dfx_json(f.path(), None).unwrap();
        assert!(configs.is_empty());
    }

    #[test]
    fn test_skips_canister_without_webmcp_section() {
        let f = write_temp_json(
            r#"{
              "canisters": {
                "frontend": { "type": "assets" },
                "backend": {
                  "candid": "backend.did",
                  "webmcp": { "name": "Backend" }
                }
              }
            }"#,
        );

        let configs = configs_from_dfx_json(f.path(), None).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].0, "backend");
    }

    #[test]
    fn test_multiple_canisters() {
        let f = write_temp_json(
            r#"{
              "canisters": {
                "ledger": {
                  "candid": "ledger.did",
                  "webmcp": { "name": "Ledger" }
                },
                "governance": {
                  "candid": "governance.did",
                  "webmcp": { "name": "Governance" }
                }
              }
            }"#,
        );

        let configs = configs_from_dfx_json(f.path(), None).unwrap();
        assert_eq!(configs.len(), 2);
    }

    #[test]
    fn test_canister_ids_injected() {
        let f = write_temp_json(
            r#"{
              "canisters": {
                "backend": {
                  "candid": "backend.did",
                  "webmcp": { "name": "Backend" }
                }
              }
            }"#,
        );

        let mut ids = BTreeMap::new();
        ids.insert(
            "backend".to_string(),
            "ryjl3-tyaaa-aaaaa-aaaba-cai".to_string(),
        );

        let configs = configs_from_dfx_json(f.path(), Some(&ids)).unwrap();
        assert_eq!(
            configs[0].1.canister_id.as_deref(),
            Some("ryjl3-tyaaa-aaaaa-aaaba-cai")
        );
    }

    #[test]
    fn test_defaults_canister_name_when_no_name() {
        let f = write_temp_json(
            r#"{
              "canisters": {
                "my_service": {
                  "candid": "service.did",
                  "webmcp": {}
                }
              }
            }"#,
        );

        let configs = configs_from_dfx_json(f.path(), None).unwrap();
        assert_eq!(configs[0].1.name.as_deref(), Some("my_service"));
    }

    #[test]
    fn test_load_canister_ids_ic_network() {
        let f = write_temp_json(
            r#"{
              "backend": { "ic": "ryjl3-tyaaa-aaaaa-aaaba-cai", "local": "bd3sg-teaaa-aaaaa-qaaba-cai" },
              "frontend": { "ic": "qoctq-giaaa-aaaaa-aaaea-cai" }
            }"#,
        );

        let ids = load_canister_ids(f.path(), "ic").unwrap();
        assert_eq!(ids["backend"], "ryjl3-tyaaa-aaaaa-aaaba-cai");
        assert_eq!(ids["frontend"], "qoctq-giaaa-aaaaa-aaaea-cai");
        assert!(!ids.contains_key("missing"));
    }

    #[test]
    fn test_load_canister_ids_local_network() {
        let f = write_temp_json(
            r#"{
              "backend": { "ic": "ryjl3-tyaaa-aaaaa-aaaba-cai", "local": "bd3sg-teaaa-aaaaa-qaaba-cai" }
            }"#,
        );

        let ids = load_canister_ids(f.path(), "local").unwrap();
        assert_eq!(ids["backend"], "bd3sg-teaaa-aaaaa-qaaba-cai");
    }
}
