//! # ic-webmcp-codegen
//!
//! Generate WebMCP (Web Model Context Protocol) tool manifests from
//! Internet Computer Candid interface definitions.
//!
//! WebMCP enables AI agents to discover and call structured tools on websites.
//! This crate bridges IC's Candid interfaces to WebMCP's JSON Schema format,
//! auto-generating:
//! - `webmcp.json` — tool manifest for agent discovery
//! - `webmcp.js` — browser script for tool registration

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
