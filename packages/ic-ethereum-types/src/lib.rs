//! Ethereum types used by canisters on the Internet Computer.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![forbid(missing_docs)]
#![warn(future_incompatible)]

mod address;
pub mod serde_data;

pub use address::Address;
