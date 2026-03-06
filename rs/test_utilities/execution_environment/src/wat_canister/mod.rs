//! WAT Canister
//! ============
//!
//! Overview
//! --------
//! The WAT Canister (`wat_canister`) is a test utility that dynamically generates WebAssembly Text format (`wat`) strings and compiles them into fresh, custom WebAssembly modules on the fly.
//!
//! Purpose
//! -------
//! The WAT canister was built specifically to test canister initialization and upgrade hooks that are difficult or impossible to cover with the [Universal Canister](../../../../universal_canister).
//!
//! The Universal Canister is a static binary that interprets payloads. This design makes it unsuitable for testing:
//! - **Naked initialization**: Testing the WebAssembly `(start)` function, which executes before any message arguments are available.
//! - **Structural boundaries**: Testing traps or logs that occur natively during `canister_init` or `canister_post_upgrade` without relying on a pre-compiled interpreter.
//! - **Upgrade persistence**: Testing how a module behaves when its heap is wiped during an upgrade. Since the UC relies on the heap to store instructions for hooks like `pre_upgrade`, it cannot easily carry those instructions through the heap-wiping boundary into `post_upgrade`.
//!
//! The WAT canister solves this by generating entirely new WebAssembly modules for each test, allowing developers to define native logic for `start`, `init`, `pre_upgrade`, and `post_upgrade` directly in the Wasm source.
//!
//! Architecture
//! ------------
//! Tests use the `WatCanisterBuilder` API to define exported functions and chain operations (like `debug_print`, `trap`, or `stable_grow`). The builder emits a highly specialized WebAssembly Text (`wat`) string, which is then compiled into raw Wasm bytes for execution testing.
//!
//! Memory Management & Limitations
//! ------------------------------
//! The WAT canister operates on a single page of WebAssembly memory (64KiB).
//!
//! - **Static Allocations**: The builder automatically allocates memory for string literals (used in `debug_print` and `trap`) starting from offset `1,000`.
//! - **Instruction Burning (`wait`)**: The `wait(instructions)` method simulates CPU cycles by executing a `memory.fill` loop. **This loop clobbers the memory range `[65,000, 65,100]`.**
//! - **Manual Operations**: If using manual memory operations like `stable_read(dst, ...)`, ensure the destination `dst` does not overlap with the reserved `wait()` scratchpad (starts at `65,000`) to avoid data corruption.
//!
//! Limitations
//! -----------
//! Because the WAT canister generates raw WebAssembly without a native stack, Wasm standard library, or dynamic memory management, building complex logic is highly verbose.
//! Avoid it for testing arbitrary byte operations or complex cross-canister callback maps; use the [Universal Canister](../../../../universal_canister) for those cases.

pub mod builder;
pub mod fn_builder;
pub(crate) mod render;

#[cfg(test)]
mod tests;

pub use builder::{WatCanisterBuilder, wat_canister};
pub use fn_builder::{WatFnCode, wat_fn};
