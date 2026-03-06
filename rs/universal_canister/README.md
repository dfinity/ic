Universal Canister
==================

Overview
--------
The Universal Canister (UC) is a pre-compiled WebAssembly canister used for integration and system tests across the Internet Computer. It acts as an interpreter that executes custom instruction sequences encoded within test message payloads.

Purpose
-------
Writing custom WebAssembly or Rust canisters for every test case is verbose and hard to maintain. The UC provides a single, flexible canister to execute arbitrary sequences of IC system API calls. By encoding instructions (like `call`, `reply`, or `stable_read`) into simple payloads, tests can simulate complex behaviors and cross-canister interactions dynamically.

Architecture
------------
The UC is a Rust application compiled into a static WebAssembly binary. When receiving an `update` or `query` message, it extracts instruction bytes from the payload and evaluates them using an internal stack.

The implementation is in `/impl`, while the library used by tests to build instruction payloads is in `/lib`.

*Note: The UC implementation temporarily uses its own `Cargo.lock` and is excluded from the top-level workspace build.*

Limitations
-----------
Because the UC is a static, pre-compiled WebAssembly module that operates by interpreting payloads passed into exported methods, it has strict limitations when testing initialization and upgrade hooks.

Specifically:
- **`start` function**: The UC cannot test the WebAssembly `(start)` function. This executes during module instantiation and does not have access to message arguments.
- **`canister_init` and `canister_post_upgrade`**: These hooks can only be tested if instructions are passed as the explicit initialization or upgrade argument. They cannot access instructions "pre-set" via a previous update call because `init` starts with a fresh heap and `post_upgrade` runs after the previous heap has been wiped. 
- **`canister_pre_upgrade`**: The UC can test this hook by saving instructions to the heap in a prior update call, as `pre_upgrade` executes while the old heap is still active.

For testing native `start` behavior, complex initialization traps, or structural Wasm properties, use the [WAT Canister](../test_utilities/execution_environment/src/wat_canister).
