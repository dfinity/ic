//! Tool registry.
//!
//! v1 tools are statically defined Rust types implementing `rig::tool::Tool`.
//! New tools are added by creating a new sibling module and re-exporting it
//! here. The agent in `providers::AiProvider::prompt` wires every entry
//! returned by [`registered_tool_names`] into the agent at construction
//! time.

pub mod calculator;
pub mod current_datetime;
// `ic_logs` is currently a TODO stub — see the module docs in
// `ic_logs.rs`. Kept in the tree (not deleted) so the placeholder
// stays visible to anyone browsing the tools directory.
pub mod ic_logs;
pub mod ic_metrics;
pub mod ic_state;
pub mod node_directory;
pub mod registry;

pub use calculator::Calculator;
pub use current_datetime::CurrentDateTime;
pub use ic_metrics::IcMetrics;
pub use ic_state::IcState;
pub use registry::{registered_tool_names, validate_tool_names};
