//! Tool name registry. The actual tool *types* are wired into the agent
//! via [`crate::providers::AiProvider::build_agent`]; this module just
//! exposes their *names* so requests can be validated against the set of
//! supported tools.

use rig::tool::Tool;

use super::{Calculator, CurrentDateTime};

/// Returns the names of all built-in tools.
pub fn registered_tool_names() -> &'static [&'static str] {
    &[Calculator::NAME, CurrentDateTime::NAME]
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
