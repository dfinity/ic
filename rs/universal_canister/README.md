Universal Canister
==================

What it is
----------

The Universal Canister (UC) is a pre-compiled WebAssembly canister used for a multitude of integration and system tests across the Internet Computer. It acts as an interpreter that executes a custom bytecode encoded within test message payloads.

Problem it solves
-----------------

Writing custom WebAssembly or Rust canisters for every single test case is verbose and hard to maintain. The Universal Canister solves this by providing a single, flexible canister that can execute arbitrary sequences of IC system API calls dynamically. By encoding instructions (like `push`, `reply`, `call`, or API calls like `stable_read`) into an update or query payload, tests can simulate complex canister behaviors and cross-canister interactions succinctly from the outside.

High-level implementation
-------------------------

The UC is a standard Rust application compiled into a static WebAssembly binary. When a test sends an `update` or `query` message, the canister extracts the custom instruction bytes from the message payload, pushes or pops values using an internal stack, and executes the simulated workflow.

The implementation of the universal canister is in `/impl`, while the library that tests use to build the instruction payloads and interface with the universal canister is in `/lib`.

Note that the universal canister's implementation is temporarily using its `Cargo.lock` file and is excluded from being built in the top-level workspace. In the future, it will be integrated into the top-level workspace and its `Cargo.lock` will be merged.

Limitations & Alternatives
--------------------------

Because the Universal Canister is a static, pre-compiled WebAssembly module that interprets payloads at runtime, it cannot be used to test structural WebAssembly behaviors. 

Specifically, you cannot use the Universal Canister to:
- Test WebAssembly module boundaries (e.g., missing exports or overlapping memory).
- Test hypervisor traps that occur during module instantiation or initialization.
- Test initialization structures like `(start)` or explicit `init`/`pre_upgrade` hooks that execute before the message payload is processed.

For testing these structural WebAssembly properties, hypervisor limits, and module initialization states, use the [WAT Canister](../test_utilities/execution_environment/src/wat_canister) instead.
