//! This module is for collecting replica stats and sending to a reporting canister

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;

/// Config settings from command line
mod cli;
pub use cli::Cli;
