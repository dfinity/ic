//! Tool registry.
//!
//! v1 tools are statically defined Rust types implementing `rig::tool::Tool`.
//! New tools are added by creating a new sibling module and re-exporting it
//! here. The agent in `providers::AiProvider::build_agent` wires every entry
//! returned by [`registered_tool_names`] into the agent at construction
//! time.

pub mod calculator;
pub mod current_datetime;
pub mod registry;

pub use calculator::Calculator;
pub use current_datetime::CurrentDateTime;
pub use registry::{registered_tool_names, validate_tool_names};
