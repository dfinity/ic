//! This package provides various utility types and function that are too small
//! to live in a separate package.

pub mod byte_slice_fmt;
pub mod deserialize;
#[cfg(unix)]
pub mod deterministic_operations;
pub mod rle;
pub mod serde_arc;
pub mod str;
pub mod thread;
