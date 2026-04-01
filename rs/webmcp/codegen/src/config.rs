//! Configuration for WebMCP generation, read from dfx.json or direct API.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// WebMCP generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the .did file
    pub did_file: PathBuf,
    /// Canister ID (optional, embedded in manifest)
    pub canister_id: Option<String>,
    /// Human-readable canister name
    pub name: Option<String>,
    /// Description for AI agents
    pub description: Option<String>,
    /// Which methods to expose (None = all)
    pub expose_methods: Option<Vec<String>>,
    /// Which methods require authentication
    pub require_auth: Vec<String>,
    /// Which query methods support certified responses
    pub certified_queries: Vec<String>,
    /// Human-readable descriptions for methods
    pub method_descriptions: BTreeMap<String, String>,
    /// Human-readable descriptions for parameters (format: "method.param")
    pub param_descriptions: BTreeMap<String, String>,
}

impl Config {
    /// Create a minimal config from just a .did file path.
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
