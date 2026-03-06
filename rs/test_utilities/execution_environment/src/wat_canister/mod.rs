//! # WAT Canister
//!
//! A test utility that dynamically generates WebAssembly Text format (`wat`)
//! strings and compiles them into fresh, custom modules on the fly.
//!
//! ## Purpose
//!
//! Built specifically to test canister initialization and upgrade hooks that are
//! difficult to cover with the Universal Canister (UC). The UC is a static
//! binary that interprets payloads, making it unsuitable for:
//!
//! - **Naked initialization**: Testing the Wasm `(start)` function, which runs
//!   before any message arguments are available.
//! - **Structural boundaries**: Testing traps or logs that occur natively
//!   during `canister_init` or `canister_post_upgrade`.
//! - **Upgrade persistence**: Testing behavior across heap wipes. Since the UC
//!   relies on the heap to store instructions, it cannot carry them from
//!   `pre_upgrade` to `post_upgrade`.
//!
//! ## Architecture
//!
//! Tests use the [`WatCanisterBuilder`] API to define exported functions and
//! chain operations (like `debug_print`, `trap`, or `stable_grow`). The builder
//! emits a specialized `wat` string, which is then compiled for testing.
//!
//! ## Memory Management & Limitations
//!
//! The canister operates on a single page of memory (64KiB).
//!
//! - **Static Allocations**: String literals are automatically allocated
//!   starting from offset `1,000`.
//! - **Instruction Burning**: The [`WatFnCode::wait`] method simulates cycles
//!   by executing `memory.fill`, which clobbers the range `[65,000, 65,100]`.
//! - **Manual Operations**: If using `stable_read` with a custom destination,
//!   ensure it does not overlap with the reserved scratchpad at `65,000`.
//!
//! ## When to Avoid
//!
//! Generating raw Wasm without a stack or standard library is verbose.
//! Use the Universal Canister for complex functional logic or multi-message
//! callback maps.

pub mod builder;
pub mod fn_builder;
pub(crate) mod render;

#[cfg(test)]
mod tests;

pub use builder::{WatCanisterBuilder, wat_canister};
pub use fn_builder::{WatFnCode, wat_fn};
