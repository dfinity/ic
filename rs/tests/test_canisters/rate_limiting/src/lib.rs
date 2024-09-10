#[cfg(target_family = "wasm")]
pub mod canister;

#[cfg(target_family = "wasm")]
pub use canister::*;
