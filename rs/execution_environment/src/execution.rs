// Replicated messages.
pub mod call_or_task;
pub mod response;
// Non-replicated messages.
pub mod nonreplicated_query;
mod nonreplicated_response;

pub mod install;
pub mod install_code;
pub mod upgrade;

// Common helpers.
pub(crate) mod common;
pub mod inspect_message;
