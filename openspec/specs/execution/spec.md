# IC Execution Environment Specification

**Crates**: `ic-execution-environment`

This is the top-level specification for the Internet Computer execution subsystem. The execution environment is the core engine responsible for running canister Wasm code, managing canister state, accounting for cycles, and orchestrating execution rounds.

## Architecture Overview

The execution subsystem consists of the following major components:

- **Scheduler** (`rs/execution_environment/src/scheduler.rs`): Orchestrates execution rounds, assigns canisters to threads, and manages round-level resource budgets.
- **ExecutionEnvironment** (`rs/execution_environment/src/execution_environment.rs`): Handles management canister (subnet) messages and coordinates canister message execution.
- **Hypervisor** (`rs/execution_environment/src/hypervisor.rs`): Interfaces between the execution layer and the Wasm executor, managing compilation and execution state creation.
- **CanisterManager** (`rs/execution_environment/src/canister_manager.rs`): Manages canister lifecycle operations (create, install, update settings, stop, delete).
- **CyclesAccountManager** (`rs/cycles_account_manager/src/lib.rs`): Handles all cycles-related accounting (fees, freezing threshold, transfers).
- **WasmExecutor** (`rs/embedders/src/wasm_executor.rs`): Executes Wasm code either in-process or via sandbox processes.
- **System API** (`rs/embedders/src/wasmtime_embedder/system_api.rs`): Implements the IC System API functions available to canisters.
- **Canister Sandbox** (`rs/canister_sandbox/`): Out-of-process execution isolation for canister Wasm code.
- **Query Handler** (`rs/execution_environment/src/query_handler/`): Handles non-replicated query execution, composite queries, and query caching.
- **Compilation Cache** (`rs/embedders/src/compilation_cache.rs`): Caches compiled Wasm modules to avoid redundant compilation.

## Detailed Specifications

The execution environment specification is split into the following files:

1. **[Wasm Execution](wasm-execution.md)**: Wasm validation, compilation, caching, instruction metering, and the Hypervisor.
2. **[Canister Lifecycle](canister-lifecycle.md)**: Creation, install_code (install/reinstall/upgrade), uninstall, start/stop, deletion, settings, and chunk store.
3. **[Cycles Accounting](cycles.md)**: Execution fees, storage fees, freezing threshold, resource reservation, cycles transfer, and minting.
4. **[Scheduler](scheduler.md)**: Round execution structure, inner round iterations, priority scheduling, heap delta management, and long-running execution management.
5. **[Message Execution](message-execution.md)**: Update calls, response callbacks, system tasks (heartbeat, timer, on_low_wasm_memory), and inspect message.
6. **[Query Execution](query-execution.md)**: Non-replicated queries, composite queries, query caching, query scheduling, and query stats.
7. **[Memory Management](memory-management.md)**: Heap memory, stable memory, memory allocation, subnet memory, and dirty page tracking.
8. **[Canister Sandboxing](canister-sandboxing.md)**: Sandbox process management, sandboxed execution, memory sharing, and compiler sandbox.
9. **[Deterministic Time Slicing](deterministic-time-slicing.md)**: Pausing and resuming executions, instruction limits, multi-stage DTS, and abort handling.
10. **[System API](system-api.md)**: Message operations, inter-canister calls, cycles operations, certified data, timers, stable memory API, and performance counters.
11. **[Canister Snapshots](canister-snapshots.md)**: Taking, loading, listing, deleting snapshots and data upload/download.
12. **[Canister Logging](canister-logging.md)**: Log production, access control, filtering, and storage.

## Key Invariants

### Determinism
- All replicated execution must be fully deterministic across all replicas.
- Non-determinism sources (randomness, time) are provided through the System API from consensus.
- DTS preserves determinism: the execution result is identical regardless of slice boundaries.

### Resource Boundedness
- Every execution round has a bounded instruction budget.
- Every message execution has a bounded instruction limit.
- Heap delta production is bounded per round to ensure checkpointing keeps up.
- Subnet memory capacity is enforced across all canisters.

### Cycles Conservation
- Cycles are neither created nor destroyed during normal execution (only minting creates new cycles).
- Execution fees are prepaid and unused portions are refunded.
- Cycles sent in inter-canister calls are either accepted by the callee or refunded in the response.

### Isolation
- Canister Wasm execution is sandboxed in separate processes.
- Each canister has its own memory space.
- Cross-canister communication only happens through the message passing System API.
- Non-replicated queries do not modify replicated state.
