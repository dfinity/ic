//! # ic-webmcp-codegen
//!
//! Generate [WebMCP](https://webmcp.link/) tool manifests from Internet Computer
//! Candid interface definitions (`.did` files).
//!
//! WebMCP is a W3C browser API (Chrome 146+) that lets websites expose structured,
//! callable tools to AI agents via `navigator.modelContext`. This crate bridges IC's
//! Candid interfaces to WebMCP's JSON Schema format, producing:
//!
//! - `webmcp.json` — tool manifest for agent discovery (served at `/.well-known/webmcp.json`)
//! - `webmcp.js` — browser script for automatic tool registration
//!
//! ## Quick Start — from a `.did` file
//!
//! ```no_run
//! use ic_webmcp_codegen::{Config, generate_manifest};
//! use std::collections::BTreeMap;
//!
//! let config = Config {
//!     did_file: "ledger.did".into(),
//!     canister_id: Some("ryjl3-tyaaa-aaaaa-aaaba-cai".into()),
//!     name: Some("ICP Ledger".into()),
//!     description: Some("ICP token ledger".into()),
//!     expose_methods: None,  // None = expose all service methods
//!     require_auth: vec!["transfer".into()],
//!     certified_queries: vec!["account_balance".into()],
//!     method_descriptions: BTreeMap::new(),
//!     param_descriptions: BTreeMap::new(),
//! };
//!
//! let manifest = generate_manifest(&config)?;
//! let json = serde_json::to_string_pretty(&manifest)?;
//! std::fs::write("webmcp.json", json)?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! ## Quick Start — from a `dfx.json` project
//!
//! ```no_run
//! use ic_webmcp_codegen::{configs_from_dfx_json, generate_manifest};
//!
//! let configs = configs_from_dfx_json("dfx.json".as_ref(), None)?;
//! for (canister_name, config) in configs {
//!     let manifest = generate_manifest(&config)?;
//!     let json = serde_json::to_string_pretty(&manifest)?;
//!     std::fs::write(format!("{canister_name}.webmcp.json"), json)?;
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! ## Modules
//!
//! - [`config`] — [`Config`] struct for controlling what is generated
//! - [`dfx_config`] — parse `dfx.json` into one `Config` per WebMCP-enabled canister
//! - [`did_parser`] — parse `.did` files into method definitions
//! - [`schema_mapper`] — map Candid types to JSON Schema
//! - [`manifest`] — generate the [`WebMCPManifest`] from a `Config`
//! - [`js_emitter`] — generate the `webmcp.js` browser registration script

pub mod config;
pub mod dfx_config;
pub mod did_parser;
pub mod js_emitter;
pub mod manifest;
pub mod schema_mapper;

pub use config::Config;
pub use dfx_config::{configs_from_dfx_json, load_canister_ids};
pub use did_parser::ParsedInterface;
pub use manifest::{WebMCPManifest, generate_manifest};
