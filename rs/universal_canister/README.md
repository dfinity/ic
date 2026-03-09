Universal Canister
==================

Overview
--------
The Universal Canister (UC) is a pre-compiled WebAssembly canister used for unit, integration, and system tests across the Internet Computer. It acts as an interpreter that executes custom instruction sequences encoded within test message payloads.

Purpose
-------
Writing custom canisters (e.g., in WAT or Rust) for every test case is verbose and hard to maintain. The UC provides a single, flexible canister to execute sequences of IC system API calls. By encoding instructions (like `call`, `reply`, or `stable_read`) into test message payloads, tests can simulate complex behaviors and cross-canister interactions dynamically.

Architecture
------------
The UC is a canister that implements a custom instruction interpreter. 
It executes arbitrary sequences of IC System API calls by evaluating instructions received via the **payload** of standard `update` or `query` calls.

The implementation is split into:
- `/impl`: The source code for the WebAssembly module that performs the evaluation.
- `/lib`: A Rust library that provides a DSL (starting with `wasm()`) to programmatically "script" the canister's behavior by constructing these instruction payloads.

*Note: The UC implementation temporarily uses its own `Cargo.lock` and is excluded from the top-level workspace build.*

Limitations
-----------
Because the UC is a generic canister that interprets payloads passed into its exported methods, it has strict limitations when testing initialization and upgrade hooks.

Specifically:
- **`start` function**: The UC cannot test the WebAssembly `(start)` function. This executes during module instantiation and does not have access to message arguments.
- **`canister_init` and `canister_post_upgrade`**: These hooks can only be tested if instructions are passed as the explicit initialization or upgrade argument. This is because the UC's mechanism for "pre-setting" instructions (used for `heartbeat` or `pre_upgrade`) relies on storing them in a global heap variable. Since `init` starts with a fresh heap and `post_upgrade` executes after the previous heap has been wiped, they cannot retrieve any instructions that were pre-set in the old instance via an `update` call.
- **Native Traps**: The UC cannot test native WebAssembly traps (e.g., division by zero) or their corresponding logs. It only performs explicit `trap` calls as requested by instructions in the payload.
- **`canister_pre_upgrade`**: The UC can test this hook by saving instructions to the heap in a prior update call, as `pre_upgrade` executes while the old heap is still active.

For testing the `start` function, or for cases where the behavior must be part of the canister module itself rather than being passed as an argument, use the [WAT Canister](../test_utilities/execution_environment/src/wat_canister).
