# Wasm Execution

**Crates**: `ic-wasm-types`

This specification covers WebAssembly compilation, validation, instrumentation, and execution on the Internet Computer.

## Requirements

### Requirement: Wasm Module Validation

All Wasm modules must pass validation before they can be installed on a canister. Validation enforces IC-specific constraints beyond standard Wasm validation.

#### Scenario: Valid system function exports
- **WHEN** a Wasm module exports functions named `canister_init`, `canister_inspect_message`, `canister_pre_upgrade`, `canister_post_upgrade`, `canister_heartbeat`, `canister_global_timer`, or `canister_on_low_wasm_memory`
- **THEN** validation succeeds for those system function exports
- **AND** each system function must have the correct signature (no params, no return values)

#### Scenario: Reserved symbol exports rejected
- **WHEN** a Wasm module exports symbols reserved by the IC runtime (e.g., `canister counter_instructions`, `canister_start`, dirty/accessed page counter globals, or stable memory names)
- **THEN** validation fails with a `WasmValidationError`

#### Scenario: Function complexity limit
- **WHEN** a Wasm function exceeds the complexity limit of 1,000,000
- **THEN** validation fails

#### Scenario: Function size limit
- **WHEN** a Wasm function body exceeds 1,000,000 instructions
- **THEN** validation fails

#### Scenario: Code section size limit
- **WHEN** the Wasm code section exceeds 12 MiB
- **THEN** validation fails

#### Scenario: Maximum Wasm memory size
- **WHEN** a Wasm module declares a memory that could exceed 4 GiB (the 32-bit addressable limit)
- **THEN** validation enforces the 32-bit Wasm memory limit of 64K pages (4 GiB)

#### Scenario: Stable memory size limit
- **WHEN** a canister attempts to use stable memory beyond the maximum allowed stable memory
- **THEN** the operation fails with an appropriate error

### Requirement: Wasm Compilation and Caching

Wasm modules are compiled to native code via Wasmtime. Compilation results are cached to avoid redundant work.

#### Scenario: First compilation of a new module
- **WHEN** a new Wasm module is installed that has not been compiled before
- **THEN** the module is validated, instrumented, and compiled to native code
- **AND** the compilation result is stored in the compilation cache keyed by Wasm hash
- **AND** compilation metrics are recorded (time, largest function instruction count, max complexity, code section size)

#### Scenario: Cache hit on subsequent installation
- **WHEN** a Wasm module is installed whose hash already exists in the compilation cache
- **THEN** the cached compiled module is reused without recompilation
- **AND** the compilation cost may be adjusted (reduced) based on `CompilationCostHandling`

#### Scenario: Compilation cost charging
- **WHEN** a Wasm module is compiled
- **THEN** instructions proportional to the decoded Wasm size are charged (`cost_to_compile_wasm_instruction * wasm_size`)
- **AND** the round instruction limit is decreased accordingly

#### Scenario: Compilation cache eviction
- **WHEN** the compilation cache exceeds its memory capacity (default 10 GiB) or disk capacity (default 100 GiB) or entry count limit (500,000)
- **THEN** least-recently-used entries are evicted

#### Scenario: Compilation error caching
- **WHEN** a Wasm module fails to decode or compile
- **THEN** the error is cached so that subsequent attempts with the same module immediately fail without re-attempting compilation

### Requirement: Wasm Execution via Hypervisor

The Hypervisor orchestrates Wasm execution by delegating to the WasmExecutor (either sandboxed or in-process).

#### Scenario: Creating an execution state
- **WHEN** `Hypervisor::create_execution_state` is called with a canister module
- **THEN** the module is decoded to estimate instruction count
- **AND** the WasmExecutor creates an `ExecutionState` containing the compiled module, exported functions, Wasm memory, stable memory, and globals
- **AND** the compilation cost is deducted from round limits

#### Scenario: Executing a Wasm function
- **WHEN** `Hypervisor::execute` is called with a `FuncRef` and `ApiType`
- **THEN** the WasmExecutor runs the function in the appropriate system API context
- **AND** returns `WasmExecutionResult` which is either `Finished` or `Paused`

#### Scenario: Execution with deterministic time slicing (DTS)
- **WHEN** a Wasm execution exceeds the slice instruction limit
- **THEN** execution is paused and a `PausedWasmExecution` is returned
- **AND** the execution can be resumed in a subsequent round
- **AND** the total instruction limit across all slices is the message instruction limit

### Requirement: System API Types

Different execution contexts provide different System API capabilities.

#### Scenario: Start API context
- **WHEN** the `canister_start` function is executed
- **THEN** only a limited System API is available (no message operations, no cycles operations)
- **AND** the canister cannot call `msg_reply`, `msg_reject`, or make inter-canister calls

#### Scenario: Init API context
- **WHEN** `canister_init` or `canister_post_upgrade` is executed
- **THEN** the caller principal and incoming payload are available
- **AND** the canister can set certified data and access stable memory
- **AND** the canister cannot make inter-canister calls

#### Scenario: Update API context
- **WHEN** an update method is executed
- **THEN** the full System API is available including message operations, cycles operations, and inter-canister calls
- **AND** the canister can call `msg_reply`, `msg_reject`, `call_new`, `call_perform`, etc.

#### Scenario: Replicated query API context
- **WHEN** a query method is executed in replicated mode (via ingress or inter-canister request)
- **THEN** message read operations are available but inter-canister calls are not
- **AND** the canister can call `msg_reply` or `msg_reject`

#### Scenario: Non-replicated query API context
- **WHEN** a query method is executed in non-replicated mode (via HTTP query endpoint)
- **THEN** the data certificate is available via `ic0.data_certificate_copy`
- **AND** inter-canister calls are not available
- **AND** changes to canister state are not persisted

#### Scenario: Composite query API context
- **WHEN** a composite query method is executed
- **THEN** inter-canister query calls can be made via `call_new` and `call_perform`
- **AND** the data certificate is available
- **AND** changes to canister state are not persisted

#### Scenario: Callback API contexts (Reply/Reject)
- **WHEN** a reply or reject callback is executed
- **THEN** the incoming payload (reply data or reject context) is available
- **AND** the canister can make further inter-canister calls
- **AND** incoming cycles from the response refund are available

#### Scenario: Cleanup API context
- **WHEN** a cleanup callback is executed (after reply/reject callback traps)
- **THEN** only a limited System API is available
- **AND** the canister cannot make inter-canister calls or reply

#### Scenario: Inspect message API context
- **WHEN** `canister_inspect_message` is executed
- **THEN** the caller, method name, and payload are available
- **AND** the canister calls `ic0.accept_message()` to accept the message
- **AND** if the canister does not call `accept_message`, the message is rejected

#### Scenario: System task API context (heartbeat, global timer, on_low_wasm_memory)
- **WHEN** a heartbeat, global timer, or on_low_wasm_memory callback is executed
- **THEN** the canister can make inter-canister calls
- **AND** there is no incoming message payload

### Requirement: Instruction Limits

Execution is bounded by instruction limits to ensure deterministic and bounded execution.

#### Scenario: Message instruction limit
- **WHEN** a message execution exceeds its total message instruction limit
- **THEN** execution fails with `InstructionLimitExceeded`
- **AND** any state changes from the failed execution are rolled back

#### Scenario: Slice instruction limit with DTS
- **WHEN** DTS is enabled and a single slice exceeds the slice instruction limit
- **THEN** execution is paused (not failed) at the end of the slice
- **AND** the remaining message instruction budget is reduced by the instructions executed in the slice

#### Scenario: Instruction limits for multi-step operations
- **WHEN** an install or upgrade operation has multiple steps (start, init/post_upgrade)
- **THEN** the message instruction limit is shared across all steps
- **AND** each step's used instructions reduce the remaining budget for subsequent steps

### Requirement: Dirty Page Overhead

Writing to memory pages incurs additional instruction costs.

#### Scenario: Dirty page counting
- **WHEN** a Wasm execution writes to heap or stable memory pages
- **THEN** additional instructions are charged proportional to the number of dirty pages
- **AND** the overhead per dirty page is configurable via `dirty_page_overhead`
