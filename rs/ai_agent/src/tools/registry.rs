//! Tool name registry. The actual tool *types* are wired into the agent
//! via [`crate::providers::AiProvider::prompt`]; this module just
//! exposes their *names* so requests can be validated against the set of
//! supported tools.

use rig::tool::Tool;

use super::{Calculator, CurrentDateTime, IcMetrics, IcState};

/// Returns the names of all built-in tools.
///
/// `ic_logs` is intentionally absent: the module is currently a TODO
/// stub (see `ic_logs.rs`). It will be added back here once the
/// implementation lands.
pub fn registered_tool_names() -> &'static [&'static str] {
    &[
        Calculator::NAME,
        CurrentDateTime::NAME,
        IcState::NAME,
        IcMetrics::NAME,
    ]
}

/// Validates that every name in `requested` exists in the registry.
/// Returns the first unknown name on error.
pub fn validate_tool_names(requested: &[String]) -> Result<(), String> {
    for name in requested {
        if !registered_tool_names().contains(&name.as_str()) {
            return Err(name.clone());
        }
    }
    Ok(())
}
