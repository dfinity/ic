# Embedders Specification

- **Crate**: `ic-embedders`
- **Source**: `rs/embedders/`
- **Purpose**: Provides the WebAssembly compilation and execution engine for IC canisters. Built on Wasmtime, this crate validates, instruments, compiles, caches, and executes Wasm binaries while enforcing IC-specific constraints such as instruction metering, memory limits, deterministic time slicing support, and system API access control.

## Requirements

### Requirement: Wasm Binary Validation

All canister Wasm modules must pass validation before they can be compiled and executed. Validation enforces IC-specific constraints beyond the standard Wasm specification.

#### Scenario: Reserved symbol export rejection
- **WHEN** a Wasm module exports any of the reserved symbols: `canister counter_instructions`, `canister_start`, `canister_counter_dirty_pages`, `canister_counter_accessed_pages`, `canister heap_page_budget`, `stable_memory`, or `stable_bytemap_memory`
- **THEN** validation fails with a `WasmValidationError`
- **AND** the module is rejected

#### Scenario: Valid system function exports
- **WHEN** a Wasm module exports functions with names matching the system function conventions
- **THEN** only the following lifecycle hooks are accepted: `canister_init`, `canister_inspect_message`, `canister_pre_upgrade`, `canister_post_upgrade`, `canister_heartbeat`, `canister_global_timer`, `canister_on_low_wasm_memory`
- **AND** user-defined query and update methods must follow `canister_query <name>`, `canister_composite_query <name>`, or `canister_update <name>` naming conventions

#### Scenario: System API import validation
- **WHEN** a Wasm module imports functions from the `ic0` module
- **THEN** each import is validated against the known system API function signatures
- **AND** imports with incorrect parameter or return types are rejected
- **AND** Wasm32-only APIs (e.g., `stable_size`, `stable_grow`, `stable_read`, `stable_write`, `call_cycles_add`, `canister_cycle_balance`, `msg_cycles_available`, `msg_cycles_refunded`, `msg_cycles_accept`) are rejected for Wasm64 modules

#### Scenario: Function complexity limit enforcement
- **WHEN** a Wasm function body is analyzed during validation
- **THEN** its complexity must not exceed the limit of 1,000,000
- **AND** its size must not exceed 1,000,000 instructions
- **AND** the code section must not exceed 12 MiB

#### Scenario: Wasm64 memory detection
- **WHEN** a Wasm module contains a 64-bit memory export named `memory`
- **THEN** it is detected as a Wasm64 module
- **AND** the appropriate memory size limits and system API variants are applied

#### Scenario: Custom section count limit
- **WHEN** the raw Wasm module is streamed once, before Wasmtime or Wirm parse it, to count custom sections and the code section size
- **THEN** validation fails with `WasmValidationError::TooManyCustomSections` if the module contains more than 1024 custom sections in total, including sections that are not `icp:public`/`icp:private` metadata
- **AND** the code section size recorded during this same pass is still checked against the 12 MiB limit

---

### Requirement: Wasm Instrumentation

After validation, Wasm modules are instrumented to inject IC-specific metering and control mechanisms before compilation.

#### Scenario: Instruction counter injection
- **WHEN** a Wasm module is instrumented
- **THEN** a global mutable i64 counter (`canister counter_instructions`) is inserted and exported
- **AND** at every reentrant basic block (function entry, loop body), a counter overflow check is injected that calls `out_of_instructions` if the counter goes below zero
- **AND** at every non-reentrant basic block, the counter is decremented by the cost of instructions in that block without an overflow check

#### Scenario: Bulk memory instruction metering
- **WHEN** a Wasm module contains bulk memory operations (e.g., `memory.copy`, `memory.fill`, `table.copy`)
- **THEN** a helper function is injected that decrements the instruction counter by the runtime-determined size argument
- **AND** if the counter goes below zero, `out_of_instructions` is called

#### Scenario: System API function injection
- **WHEN** a Wasm module is instrumented
- **THEN** up to five system API imports are injected: `out_of_instructions`, `try_grow_wasm_memory`, `try_grow_stable_memory`, `internal_trap`, and `stable_read_first_access`
- **AND** the last three are only injected when Wasm-native stable memory is enabled

#### Scenario: Start section rewriting
- **WHEN** a Wasm module has a `start` section
- **THEN** the start function is re-exported as `canister_start`
- **AND** the start section is removed from the module
- **AND** this allows the runtime to set the instruction counter before executing initialization

#### Scenario: Stable memory instrumentation
- **WHEN** Wasm-native stable memory is enabled
- **THEN** two additional memories are inserted: `stable_memory` (64-bit, up to max stable memory size) and `stable_bytemap_memory` (32-bit, for tracking dirty pages)
- **AND** the stable bytemap memory index is one greater than the stable memory index

#### Scenario: Dirty and accessed page counter globals
- **WHEN** a Wasm module is instrumented
- **THEN** mutable globals for dirty page and accessed page counters are inserted
- **AND** these globals are exported for the runtime to read after execution

#### Scenario: Heap page budget global
- **WHEN** a Wasm module is instrumented
- **THEN** a fourth exported mutable global, `canister heap_page_budget`, is inserted
- **AND** `new_instance` initialises it to the heap page limit of the execution's API type, and the deterministic memory tracker decrements it once for each Wasm page it newly maps (`on_wasm_page_accessed`), so the module itself can tell how many pages it may still touch

---

### Requirement: Wasm Compilation and Caching

Compiled Wasm modules are cached to avoid redundant recompilation across executions.

#### Scenario: First-time compilation
- **WHEN** a canister Wasm binary has no entry in the `CompilationCache` or `EmbedderCache`
- **THEN** the binary is decoded (with optional gzip decompression)
- **AND** the binary is validated and instrumented
- **AND** the instrumented Wasm is compiled by Wasmtime into a native `Module`
- **AND** the module is pre-instantiated into an `InstancePre` for fast subsequent instantiation
- **AND** the serialized module is stored on disk in the `CompilationCache`
- **AND** a `CompilationResult` is returned containing: `largest_function_instruction_count`, `compilation_time`, `max_complexity`, and `code_section_size`

#### Scenario: Cache hit on EmbedderCache
- **WHEN** a canister's `WasmBinary` already has a populated `EmbedderCache`
- **THEN** the cached `EmbedderCache` is returned directly
- **AND** no compilation or deserialization occurs
- **AND** the `serialized_module` and `compilation_result` fields are `None`

#### Scenario: Cache hit on CompilationCache
- **WHEN** a canister's `WasmBinary` has no `EmbedderCache` but exists in the `CompilationCache`
- **THEN** the on-disk serialized module file descriptor is duplicated and read
- **AND** the module is pre-instantiated from the serialized bytes
- **AND** the result is stored in the `EmbedderCache` for future hits
- **AND** the `compilation_result` field is `None` (no recompilation needed)

#### Scenario: Compilation cache capacity management
- **WHEN** the `CompilationCache` reaches its maximum entry count (default: 500,000)
- **THEN** the least recently used entry is evicted before inserting a new one
- **AND** the cache respects both memory capacity (default: 10 GiB) and disk capacity (default: 100 GiB) limits

#### Scenario: Concurrent compilation safety
- **WHEN** multiple threads compile the same Wasm module simultaneously
- **THEN** each thread produces a uniquely named file on disk using an atomic counter
- **AND** all threads can safely insert into the `CompilationCache` without interference
- **AND** the final cache entry is consistent

#### Scenario: Compilation error caching
- **WHEN** compilation of a Wasm module fails with a `HypervisorError`
- **THEN** the error is cached in the `CompilationCache` keyed by the Wasm hash
- **AND** subsequent lookups return the cached error without reattempting compilation

---

### Requirement: Wasm Execution

The executor runs canister Wasm code in a sandboxed Wasmtime instance with IC-specific system API bindings.

#### Scenario: Execution state creation
- **WHEN** `create_execution_state` is called for a new canister
- **THEN** the Wasm binary is compiled (or retrieved from cache)
- **AND** data segments are extracted and applied to the Wasm memory page map
- **AND** the module is instantiated to obtain initial exported globals and memory size
- **AND** an `ExecutionState` is returned containing: `wasm_binary`, `exports`, `wasm_memory`, `stable_memory`, `exported_globals`, and `metadata`

#### Scenario: Message execution
- **WHEN** `execute` is called with a `WasmExecutionInput`
- **THEN** a `SystemApiImpl` is created with the given `ApiType`, `SandboxSafeSystemState`, and execution parameters
- **AND** a `WasmtimeInstance` is created from the `EmbedderCache` with the current memory state and globals
- **AND** the instruction counter is set to the first slice's instruction limit
- **AND** the Wasm function referenced by `func_ref` is executed

#### Scenario: Successful execution with modification tracking
- **WHEN** Wasm execution completes successfully and `ModificationTracking::Track` is active
- **THEN** dirty pages from both Wasm memory and stable memory are collected
- **AND** the `PageMap` for both memories is updated with the dirty page deltas
- **AND** the final exported globals are captured
- **AND** an `ExecutionStateChanges` is returned containing the updated globals and memories
- **AND** `SystemStateModifications` are extracted from the system API

#### Scenario: Successful execution without modification tracking
- **WHEN** Wasm execution completes successfully and `ModificationTracking::Ignore` is active (e.g., query calls)
- **THEN** no dirty page tracking or state changes are captured
- **AND** the `execution_state_changes` field is `None`

#### Scenario: Execution failure
- **WHEN** Wasm execution traps or encounters an error
- **THEN** the system API's `take_execution_result` is called to deallocate any pending resources
- **AND** cycles from unsent requests are returned
- **AND** a `WasmExecutionOutput` is returned with the error in `wasm_result`
- **AND** no state changes are recorded

#### Scenario: Deterministic time slicing assertion
- **WHEN** `WasmExecutorImpl::execute` is called (non-sandboxed mode)
- **THEN** message instruction limit must equal slice instruction limit
- **AND** this is enforced by an assertion because DTS requires sandboxing

---

### Requirement: Memory Management and Limits

The embedder enforces strict memory limits for canister heap and stable memory.

#### Scenario: Wasm32 memory limits
- **WHEN** a Wasm32 canister executes
- **THEN** the maximum heap memory is 4 GiB (2^32 bytes)
- **AND** the Wasm page size is 64 KiB
- **AND** a guard region of at least 8 GiB is allocated for safety
- **AND** the maximum Wasm stack size is 5 MiB

#### Scenario: Reserved pages for old Motoko canisters
- **WHEN** a canister exports `canister_update __motoko_async_helper` but does NOT have a `motoko:compiler` custom section
- **THEN** 16 Wasm pages are reserved at the end of the 4 GiB address space
- **AND** if heap size after execution exceeds `(max_wasm32_pages - 16)` pages, the error `HypervisorError::ReservedPagesForOldMotoko` is returned

#### Scenario: No reserved pages for modern canisters
- **WHEN** a canister either does not export the Motoko async helper or has the `motoko:compiler` section
- **THEN** zero pages are reserved
- **AND** the full Wasm32 address space is available

---

### Requirement: Heap Accessed-Page Limit

An execution may be limited in how many distinct Wasm heap pages it accesses. The limit is configured per API type (`EmbeddersConfig::wasm_memory_accessed_page_limit`: message, upgrade, query, in 4 KiB OS pages) and enforced only when the feature flag `FeatureFlags::wasm_memory_accessed_page_limit` is enabled. By default the flag is disabled and the limit equals the maximum Wasm64 heap size, so the limit is never hit; it exists so the limit can later be lowered per API type.

#### Scenario: Flag disabled
- **WHEN** `FeatureFlags::wasm_memory_accessed_page_limit` is disabled (the default)
- **THEN** no checks are injected into canister code and no execution fails because of the limit
- **AND** accesses beyond the limit are only counted in the metrics

#### Scenario: Wasm loads and stores beyond the limit trap
- **WHEN** the flag is enabled and a Wasm load or store faults on a page that would take the execution past its limit
- **THEN** the deterministic memory tracker's `handle_sigsegv` returns `SigsegvOutcome::Refused`: it leaves the page unmapped, sets a shared `page_limit_exceeded` flag and counts the refusal, and Wasmtime raises a trap at the faulting instruction
- **AND** write-protect faults on pages already accessed in this execution are exempt
- **AND** `run()` rewrites the execution's result to `HypervisorError` with `MemoryAccessLimitExceeded` whenever that flag is set, rather than reporting the underlying `HeapOutOfBounds` trap

#### Scenario: System API calls are pre-checked
- **WHEN** the flag is enabled and a system API call is about to read or write a heap range
- **THEN** the heap accessor asks the tracker (`check_range_fits`, a bitmap-based check of whether the byte range can be touched without crossing the limit) first, and the call fails with `MemoryAccessLimitExceeded` before it touches any page past the limit

#### Scenario: Bulk memory operations are pre-checked inside the module
- **WHEN** the flag is enabled and a module uses `memory.copy`, `memory.fill` or `memory.init`, which Wasmtime cannot unwind after a refused fault
- **THEN** instrumentation routes each of them through an injected helper that charges instructions as before, computes an upper bound on the pages the operation can touch, and proceeds directly when that bound fits in `canister heap_page_budget` (the fast path)
- **AND** otherwise calls the injected import `__.check_heap_bulk_access`, whose host side lets out-of-bounds operations proceed to their own `HeapOutOfBounds` trap and otherwise checks the exact ranges with the tracker's `check_ranges_fit` (pages shared by source and destination count once), failing with `MemoryAccessLimitExceeded` before any byte is touched

#### Scenario: Wasm-native stable memory copies are pre-checked
- **WHEN** the flag is enabled and Wasm-native stable memory is used
- **THEN** the same fast-path / slow-path check is spliced into the injected `stable_read` / `stable64_read` bodies, before their branch so that both the first-access host call and the `memory.copy` are covered, and before the heap-source `memory.copy` in `stable_write` / `stable64_write`
- **AND** with this, every heap access path is covered: loads and stores by the signal handler, system API calls by the heap accessor, and bulk operations and stable memory copies by the injected checks

#### Scenario: Refusal metrics
- **WHEN** an execution finishes
- **THEN** refusals are counted by detector (signal handler, host accessor, bulk check), together with the number of slow-path `__.check_heap_bulk_access` calls; they are reported via `InstanceStats` (`HeapPageLimitRefusals`)
- **AND** the sandboxed execution controller exports them as `sandboxed_execution_wasm_page_limit_exceeded{api_type, detector}` and `sandboxed_execution_wasm_bulk_check_slow_path_calls{api_type}`

---

### Requirement: Dirty Page Copy Optimization

For executions that dirty many memory pages, an optimization yields control to the replica to copy pages in a new execution slice.

#### Scenario: Dirty page optimization triggered
- **WHEN** a Wasm execution completes successfully
- **AND** deterministic time slicing is enabled
- **AND** the number of dirty Wasm pages exceeds `max_dirty_pages_without_optimization`
- **THEN** `yield_for_dirty_memory_copy` is called on the system API
- **AND** the instructions consumed by dirty page copying (pages * `dirty_page_copy_overhead`) are accounted in the slice output

#### Scenario: Dirty page optimization not triggered
- **WHEN** the number of dirty pages is below the threshold or DTS is disabled
- **THEN** no yielding occurs
- **AND** the dirty page overhead is zero in the slice output

---

### Requirement: Error Handling and Trap Codes

Wasmtime errors and traps are converted into IC-specific `HypervisorError` variants for consistent error reporting.

#### Scenario: Wasm trap conversion
- **WHEN** Wasmtime raises a `StackOverflow` trap
- **THEN** it is converted to `TrapCode::StackOverflow`

#### Scenario: Memory out of bounds trap
- **WHEN** Wasmtime raises a `MemoryOutOfBounds` trap
- **THEN** it is converted to `TrapCode::HeapOutOfBounds`

#### Scenario: Table out of bounds trap
- **WHEN** Wasmtime raises a `TableOutOfBounds` trap
- **THEN** it is converted to `TrapCode::TableOutOfBounds`

#### Scenario: Integer division by zero trap
- **WHEN** Wasmtime raises an `IntegerDivisionByZero` trap
- **THEN** it is converted to `TrapCode::IntegerDivByZero`

#### Scenario: Unreachable code trap
- **WHEN** Wasmtime raises an `UnreachableCodeReached` trap
- **THEN** it is converted to `TrapCode::Unreachable`

#### Scenario: Bad function signature error
- **WHEN** Wasmtime raises a `BadSignature` trap or an error containing "argument type mismatch"
- **THEN** it is converted to `HypervisorError::ToolchainContractViolation` with message "function invocation does not match its signature"

#### Scenario: Internal error codes
- **WHEN** an internal error occurs during execution
- **THEN** it is identified by one of the following codes: `HeapOutOfBounds` (1), `StableMemoryOutOfBounds` (2), `StableMemoryTooBigFor32Bit` (3), `MemoryWriteLimitExceeded` (4), `MemoryAccessLimitExceeded` (5), `StableGrowFailed` (6)
- **AND** unknown codes default to `Unknown` (0)

---

### Requirement: Wasmtime Engine Configuration

The Wasmtime engine is configured with IC-specific settings for deterministic and secure execution.

#### Scenario: Multi-memory and memory64 support
- **WHEN** the Wasmtime engine is configured for execution
- **THEN** `wasm_multi_memory` is enabled (for stable memory as a separate Wasm memory)
- **AND** `wasm_memory64` is enabled (for Wasm64 canister support)

#### Scenario: Custom memory creator
- **WHEN** a Wasmtime engine is created
- **THEN** a `WasmtimeMemoryCreator` is installed as the host memory allocator
- **AND** it tracks created memory regions for later use by `SigsegvMemoryTracker`

#### Scenario: Linker setup for Wasm32 vs Wasm64
- **WHEN** a module is pre-instantiated
- **THEN** the linker binds system API calls (syscalls) with pointer-width types matching the module's memory type
- **AND** Wasm32 modules use `u32` pointer types for syscall bindings
- **AND** Wasm64 modules use `u64` pointer types for syscall bindings

#### Scenario: Table limits
- **WHEN** a Wasmtime store is configured
- **THEN** the maximum number of tables per instance is 1
- **AND** the maximum number of table elements is 1,000,000

---

### Requirement: Canister Backtrace Support

When Wasm execution traps, the embedder attempts to provide a human-readable backtrace.

#### Scenario: Backtrace with name section
- **WHEN** a Wasm trap occurs and the module includes a `name` section
- **THEN** a `CanisterBacktrace` is generated containing function indices and demangled function names
- **AND** Rust-style mangled names are demangled for readability

#### Scenario: Backtrace without name section
- **WHEN** a Wasm trap occurs and the module does not include a `name` section
- **THEN** no backtrace is produced (returns `None`)
- **AND** the error is reported without stack trace information

#### Scenario: Backtraces are hidden from callers who may not view the canister's logs, across DTS slices
- **WHEN** the caller of an execution is not allowed to view the canister's logs (per its log visibility settings)
- **THEN** the backtrace is removed from the resulting `Trapped`, `CalledTrap` and `Cleanup` (callback and cleanup) errors
- **AND** this decision is preserved through deterministic time slicing: a paused execution is wrapped (`BacktraceFilteringPausedWasmExecution`) so that the result of every resumed slice is filtered the same way, and an execution that traps only after being paused and resumed cannot return a backtrace to an unauthorized caller
