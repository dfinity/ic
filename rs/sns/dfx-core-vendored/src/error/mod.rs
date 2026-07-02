//! Error types.
//!
//! Trimmed subset of `dfx_core::error` covering only the identity- and
//! network-resolution paths retained in this crate. See the crate-level docs in
//! [`crate`] for provenance and what was dropped.

pub mod config;
pub mod encryption;
pub mod fs;
pub mod get_user_home;
pub mod identity;
pub mod keyring;
pub mod structured_file;
