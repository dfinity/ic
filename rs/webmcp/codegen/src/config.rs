//! Configuration for WebMCP manifest generation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Configuration controlling what `ic-webmcp-codegen` generates.
///
/// A `Config` is the single input to [`generate_manifest`](crate::generate_manifest).
/// It can be built programmatically, loaded from a `dfx.json` via
/// [`configs_from_dfx_json`](crate::configs_from_dfx_json), or constructed
/// from CLI flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the Candid `.did` file to parse.
    pub did_file: PathBuf,

    /// Canister principal ID embedded in the manifest.
    ///
    /// If `None`, the `id` field is omitted from the manifest's `canister` section.
    /// The TypeScript browser library will fall back to a `canisterId` passed in
    /// `ICWebMCPConfig` at runtime.
    pub canister_id: Option<String>,

    /// Human-readable name for the canister, shown to AI agents.
    ///
    /// Defaults to `"IC Canister"` if absent.
    pub name: Option<String>,

    /// Description of what the canister does, shown to AI agents.
    ///
    /// Defaults to `"Internet Computer canister"` if absent.
    pub description: Option<String>,

    /// Which service methods to expose as WebMCP tools.
    ///
    /// If `None`, all methods in the service definition are exposed.
    /// If `Some(vec![...])`, only the named methods are included.
    pub expose_methods: Option<Vec<String>>,

    /// Methods that require Internet Identity authentication before calling.
    ///
    /// These methods will have `"requires_auth": true` in the manifest, and
    /// the browser library will prompt the user to authenticate before executing them.
    pub require_auth: Vec<String>,

    /// Query methods that return certified responses.
    ///
    /// These methods will have `"certified": true` in the manifest, indicating
    /// that the browser library should verify the BLS threshold signature on the response.
    pub certified_queries: Vec<String>,

    /// Human-readable descriptions for individual methods.
    ///
    /// Key: method name. Value: description shown to the AI agent.
    /// Methods without an entry use `"Call <method_name>"` as a fallback.
    pub method_descriptions: BTreeMap<String, String>,

    /// Human-readable descriptions for individual parameters.
    ///
    /// Key format: `"method_name.param_name"` (e.g., `"transfer.amount"`).
    /// Value: description shown to the AI agent when it prepares the argument.
    pub param_descriptions: BTreeMap<String, String>,
}

impl Config {
    /// Create a minimal config from just a `.did` file path.
    ///
    /// All optional fields are left empty. All service methods will be exposed
    /// with auto-generated descriptions, no auth requirements, and no certified queries.
    ///
    /// # Example
    ///
    /// ```
    /// use ic_webmcp_codegen::Config;
    ///
    /// let config = Config::from_did_file("ledger.did");
    /// assert!(config.expose_methods.is_none()); // all methods exposed
    /// assert!(config.require_auth.is_empty());
    /// ```
    pub fn from_did_file(path: impl Into<PathBuf>) -> Self {
        Config {
            did_file: path.into(),
            canister_id: None,
            name: None,
            description: None,
            expose_methods: None,
            require_auth: Vec::new(),
            certified_queries: Vec::new(),
            method_descriptions: BTreeMap::new(),
            param_descriptions: BTreeMap::new(),
        }
    }
}
