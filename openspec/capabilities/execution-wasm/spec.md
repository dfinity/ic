# Execution: Wasm Execution Capability Specification

**Source narrative**: `openspec/specs/execution/wasm-execution.md`
**Crates**: `ic-wasm-types`, `ic-embedders`, `ic-execution-environment`
**Key files**: `rs/embedders/src/wasm_executor.rs`, `rs/embedders/src/wasmtime_embedder.rs`, `rs/embedders/src/compilation_cache.rs`

---

## REQ-WASM-001: Wasm Module Validation

All Wasm modules MUST pass IC-specific validation before installation.

### SCENARIO-WASM-001: Valid system function exports accepted
**Given** a Wasm module exports `canister_init`, `canister_inspect_message`, `canister_pre_upgrade`, `canister_post_upgrade`, `canister_heartbeat`, `canister_global_timer`, or `canister_on_low_wasm_memory`
**When** validation runs
**Then** validation succeeds for those exports
**And** each system function must have the correct signature (no params, no return values)

### SCENARIO-WASM-002: Reserved symbol exports rejected
**Given** a Wasm module exports symbols reserved by the IC runtime
**When** validation runs
**Then** validation fails with `WasmValidationError`

### SCENARIO-WASM-003: Function complexity limit
**Given** a Wasm function exceeds complexity of 1,000,000
**When** validation runs
**Then** validation fails

### SCENARIO-WASM-004: Function size limit
**Given** a Wasm function body exceeds 1,000,000 instructions
**When** validation runs
**Then** validation fails

### SCENARIO-WASM-005: Code section size limit
**Given** the Wasm code section exceeds 12 MiB
**When** validation runs
**Then** validation fails

### SCENARIO-WASM-006: 32-bit memory limit enforcement
**Given** a Wasm module declares a memory that could exceed 4 GiB
**When** validation runs
**Then** validation enforces the 32-bit Wasm memory limit of 64K pages (4 GiB)

### SCENARIO-WASM-007: Stable memory size limit
**Given** a canister attempts to use stable memory beyond the maximum allowed
**When** the operation executes
**Then** the operation fails with an appropriate error

---

## REQ-WASM-002: Wasm Compilation and Caching

Wasm modules MUST be compiled via Wasmtime with results cached to avoid redundant work.

### SCENARIO-WASM-008: First compilation of new module
**Given** a new Wasm module is installed that has not been compiled before
**When** compilation runs
**Then** the module is validated, instrumented, and compiled to native code
**And** the result is stored in the compilation cache keyed by Wasm hash
**And** compilation metrics are recorded

### SCENARIO-WASM-009: Cache hit on subsequent installation
**Given** a Wasm module is installed whose hash already exists in the cache
**When** the installation runs
**Then** the cached compiled module is reused without recompilation
**And** the compilation cost may be reduced based on `CompilationCostHandling`

### SCENARIO-WASM-010: Compilation cost charging
**Given** a Wasm module is compiled
**When** the cost is applied
**Then** instructions proportional to decoded Wasm size are charged: `cost_to_compile_wasm_instruction * wasm_size`
**And** the round instruction limit is decreased accordingly

### SCENARIO-WASM-011: Compilation cache eviction
**Given** the compilation cache exceeds memory (10 GiB), disk (100 GiB), or entry count (500,000) limits
**When** eviction runs
**Then** least-recently-used entries are evicted

### SCENARIO-WASM-012: Compilation error caching
**Given** a Wasm module fails to decode or compile
**When** the error is cached
**Then** subsequent attempts with the same module immediately fail without re-attempting compilation

---

## REQ-WASM-003: Wasm Execution via Hypervisor

The Hypervisor MUST orchestrate Wasm execution by delegating to the WasmExecutor.

### SCENARIO-WASM-013: Creating an execution state
**Given** `Hypervisor::create_execution_state` is called with a canister module
**When** the state is created
**Then** the module is decoded to estimate instruction count
**And** the WasmExecutor creates an `ExecutionState` with compiled module, exports, Wasm memory, stable memory, and globals
**And** compilation cost is deducted from round limits

### SCENARIO-WASM-014: Executing a Wasm function
**Given** `Hypervisor::execute` is called with a `FuncRef` and `ApiType`
**When** execution runs
**Then** the WasmExecutor runs the function in the appropriate system API context
**And** returns `WasmExecutionResult` as either `Finished` or `Paused`

### SCENARIO-WASM-015: Execution with DTS
**Given** a Wasm execution exceeds the slice instruction limit
**When** the slice limit is hit
**Then** execution is paused and a `PausedWasmExecution` is returned
**And** the execution can be resumed in a subsequent round
**And** the total instruction limit across all slices is the message instruction limit

---

## REQ-WASM-004: System API Execution Contexts

Different execution contexts MUST provide different System API capabilities.

### SCENARIO-WASM-016: Start API context
**Given** the `canister_start` function executes
**When** System API calls are made
**Then** only a limited API is available (no message ops, no cycles ops, no inter-canister calls)

### SCENARIO-WASM-017: Init and post_upgrade API context
**Given** `canister_init` or `canister_post_upgrade` executes
**When** System API calls are made
**Then** caller principal and incoming payload are available
**And** certified data can be set, stable memory accessed
**And** inter-canister calls are NOT available

### SCENARIO-WASM-018: Update API context
**Given** an update method executes
**When** System API calls are made
**Then** the full System API is available: message ops, cycles ops, inter-canister calls

### SCENARIO-WASM-019: Replicated query API context
**Given** a query method executes in replicated mode
**When** System API calls are made
**Then** message read operations are available but inter-canister calls are NOT
**And** the canister can call `msg_reply` or `msg_reject`

### SCENARIO-WASM-020: Non-replicated query API context
**Given** a query method executes in non-replicated mode
**When** System API calls are made
**Then** the data certificate is available via `ic0.data_certificate_copy`
**And** inter-canister calls are NOT available
**And** state changes are NOT persisted

### SCENARIO-WASM-021: Composite query API context
**Given** a composite query method executes
**When** System API calls are made
**Then** inter-canister query calls can be made via `call_new`/`call_perform`
**And** state changes are NOT persisted

### SCENARIO-WASM-022: Reply/Reject callback API context
**Given** a reply or reject callback executes
**When** System API calls are made
**Then** incoming payload and refund cycles are available
**And** further inter-canister calls can be made

### SCENARIO-WASM-023: Cleanup API context
**Given** a cleanup callback executes (after reply/reject traps)
**When** System API calls are made
**Then** only a limited API is available
**And** inter-canister calls and replies are NOT available

### SCENARIO-WASM-024: Inspect message API context
**Given** `canister_inspect_message` executes
**When** System API calls are made
**Then** caller, method name, and payload are available
**And** calling `ic0.accept_message()` accepts the message
**And** not calling it causes the message to be rejected

---

## REQ-WASM-005: Instruction Limits

Execution MUST be bounded by instruction limits.

### SCENARIO-WASM-025: Message instruction limit exceeded
**Given** a message execution exceeds its total message instruction limit
**When** the limit is hit
**Then** execution fails with `InstructionLimitExceeded`
**And** all state changes from the failed execution are rolled back

### SCENARIO-WASM-026: Slice instruction limit with DTS
**Given** DTS is enabled and a single slice exceeds the slice instruction limit
**When** the limit is hit
**Then** execution is paused (not failed)
**And** remaining message instruction budget is reduced by instructions executed in the slice

### SCENARIO-WASM-027: Instruction limits shared across multi-step operations
**Given** an install or upgrade has multiple steps (start, init/post_upgrade)
**When** steps execute sequentially
**Then** the message instruction limit is shared across all steps
**And** each step's used instructions reduce the remaining budget

---

## REQ-WASM-006: Dirty Page Overhead

Writing to memory pages MUST incur additional instruction costs.

### SCENARIO-WASM-028: Dirty page instruction overhead
**Given** a Wasm execution writes to heap or stable memory pages
**When** dirty pages are counted
**Then** additional instructions are charged: `dirty_page_count * dirty_page_overhead`
**And** this overhead is added to the total instructions used by the execution

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-WASM-001 | Wasm validation | narrative | rs/embedders/ tests |
| REQ-WASM-002 | Compilation/caching | narrative | rs/embedders/ tests |
| REQ-WASM-003 | Hypervisor execution | narrative | rs/execution_environment/tests/ |
| REQ-WASM-004 | System API contexts | narrative | rs/execution_environment/tests/ |
| REQ-WASM-005 | Instruction limits | narrative | rs/execution_environment/tests/ |
| REQ-WASM-006 | Dirty page overhead | narrative | rs/execution_environment/tests/ |
