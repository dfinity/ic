WAT Canister
============

Overview
--------
The WAT Canister (`wat_canister`) is a test utility that dynamically generates WebAssembly Text format (`wat`) strings and compiles them into fresh WebAssembly modules on the fly. 

Purpose
-------
Certain hypervisor behaviors depend strictly on the structural layout of the WebAssembly module, such as memory overlaps, instantiation limits, infinite loop unrolling traps, and the initialization `start` function.

Because the [Universal Canister](../../../../universal_canister) uses a static, pre-compiled WebAssembly binary, it cannot simulate these properties. The WAT canister provides a unified Rust API to build specialized WebAssembly modules from scratch, allowing tests to assert exactly how the hypervisor parses and initializes strict Wasm constructs.

Architecture
------------
Tests use the `WatCanisterBuilder` API to define exported functions (like `update` or `start`) and chain operations (like `debug_print`, `trap`, or `stable_grow`) via `WatFnCode`. The builder emits a highly specialized WebAssembly Text (`wat`) string, which is then compiled into raw Wasm bytes for execution testing.

Limitations
-----------
Because the WAT canister generates raw WebAssembly without a native stack, Wasm standard library, or dynamic memory management, building complex logic is highly verbose.

Avoid the WAT canister for:
- Testing complex functional logic or arbitrary byte operations.
- Simulating multi-message cross-canister callback maps.
- Testing system APIs that don't depend strictly on WebAssembly packaging structure.

For testing functional behavior and complex cross-canister interactions via message payloads, use the [Universal Canister](../../../../universal_canister) instead.
