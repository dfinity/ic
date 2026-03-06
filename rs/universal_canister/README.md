Universal Canister
==================

Overview
--------
The Universal Canister (UC) is a pre-compiled WebAssembly canister used for integration and system tests across the Internet Computer. It acts as an interpreter that executes custom instruction sequences encoded within test message payloads.

Purpose
-------
Writing custom WebAssembly or Rust canisters for every test case is verbose and hard to maintain. The UC provides a flexible canister to execute arbitrary sequences of IC system API calls dynamically. By encoding instructions (like `call`, `reply`, or `stable_read`) into simple payloads, tests can succinctly simulate complex canister behaviors and cross-canister interactions.

Architecture
------------
The UC is a Rust application compiled into a static WebAssembly binary. When receiving an `update` or `query` message, it extracts instruction bytes from the payload and evaluates them using an internal stack.

The implementation is in `/impl`, while the library used by tests to build instruction payloads is in `/lib`.

*Note: The UC implementation temporarily uses its own `Cargo.lock` and is excluded from the top-level workspace build.*

Limitations
-----------
Because the UC is a static, pre-compiled WebAssembly module, it cannot test structural WebAssembly properties. 

You cannot use the UC to test:
- WebAssembly module boundaries (e.g., missing exports or overlapping memory).
- Hypervisor traps during module instantiation.
- Initialization structures like `(start)`, or explicit `init`/`pre_upgrade` hooks executing before the payload is processed.

For testing these structural Wasm properties and module initialization states, use the [WAT Canister](../test_utilities/execution_environment/src/wat_canister).
