WAT Canister
============

What it is
----------

The WAT Canister (`wat_canister`) is a test utility that dynamically generates WebAssembly Text format (`wat`) strings and compiles them into fresh, custom WebAssembly modules on the fly for each test. 

Problem it solves
-----------------

Some behaviors of the Internet Computer execution environment and hypervisor depend strictly on the structural layout of the WebAssembly module itself. These include module instantiation limits, Wasm memory overlaps, infinite loop unrolling traps, and initialization execution states (like the WebAssembly `start` function).

Because the `universal_canister` uses a static, pre-compiled WebAssembly binary, it cannot simulate or test these structural properties natively. The WAT canister solves this by providing a unified Rust builder API to construct specialized WebAssembly modules from scratch. This allows tests to assert exactly how the hypervisor parses, compiles, and initializes strict Wasm constructs.

High-level implementation
-------------------------

The module provides a `WatCanisterBuilder` API. Tests define exported functions (like `update`, `start`, or `init`) and chain operations (like `debug_print`, `trap`, or `stable_grow`) using `WatFnCode`. Behind the scenes, the builder emits a highly specialized WebAssembly Text (`wat`) string with exact loop bounds and memory offsets, which is then parsed and compiled into raw Wasm bytes for execution testing.

Limitations & Alternatives
--------------------------

Because the WAT canister generates raw WebAssembly without a native stack, Wasm standard library, or dynamic memory management runtime, building multi-stage logic is highly verbose and difficult to reason about.

Specifically, you should avoid the WAT canister for:
- Testing complex functional logic or arbitrary byte permutations.
- Simulating multi-message cross-canister callback maps.
- Testing cycle management and system API data that don't depend strictly on WebAssembly module packaging structure.

For testing functional behavior, sequences of system API calls, and complex multi-canister interactions via message payloads, use the [Universal Canister](../../../../universal_canister) instead.
