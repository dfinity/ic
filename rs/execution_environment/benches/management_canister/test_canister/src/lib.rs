#[cfg(target_family = "wasm")]
pub mod main;

#[cfg(target_family = "wasm")]
pub use main::*;
