# Canister Sandboxing

**Crates**: `ic-canister-sandbox-backend-lib`

This specification covers the out-of-process canister sandbox execution model.

## Requirements

### Requirement: Sandbox Architecture

Canister Wasm code executes in separate sandbox processes for isolation and security.

#### Scenario: Sandbox process creation
- **WHEN** a canister needs to execute for the first time (or its sandbox was evicted)
- **THEN** a new sandbox process is created via the launcher process
- **AND** the sandbox process is initialized with the compiled Wasm module
- **AND** communication between the replica and sandbox uses RPC over Unix domain sockets

#### Scenario: Sandbox process reuse
- **WHEN** a canister has an existing sandbox process from a previous execution
- **THEN** the sandbox process is reused for subsequent executions
- **AND** this avoids the overhead of process creation and module loading

#### Scenario: Sandbox process eviction
- **WHEN** the number of sandbox processes exceeds resource limits or system memory is low
- **THEN** least-recently-used sandbox processes are evicted
- **AND** eviction happens in batches (200 processes or 1 GiB of RSS at a time)
- **AND** memory-based eviction is triggered when available system memory falls below 250 GiB

### Requirement: Sandboxed Execution Controller

The `SandboxedExecutionController` manages the lifecycle of sandbox processes and execution.

#### Scenario: Compilation cache lookup
- **WHEN** a canister execution begins
- **THEN** the controller checks for compiled modules in this order:
  1. Embedder cache (attached to the canister's WasmBinary) - fastest, process-local
  2. Compilation cache (shared across canisters) - may need to send module to sandbox
  3. Cache miss - full compilation needed
- **AND** metrics are recorded for each cache level hit/miss

#### Scenario: Sandbox execution input preparation
- **WHEN** a canister execution is dispatched to a sandbox
- **THEN** the execution input includes:
  - The function reference to execute
  - The system API type and parameters
  - The canister's current memory state (via shared memory)
  - The execution parameters (instruction limits, etc.)

#### Scenario: Sandbox execution output processing
- **WHEN** a sandbox execution completes
- **THEN** the output includes:
  - Wasm execution output (instructions used, trap info, etc.)
  - State modifications (system state changes, new calls, etc.)
  - Dirty page lists for heap and stable memory
  - Updated exported globals

### Requirement: Deterministic Time Slicing in Sandbox

DTS allows long-running executions to be paused and resumed across rounds.

#### Scenario: Slice execution in sandbox
- **WHEN** a Wasm execution reaches the slice instruction limit in the sandbox
- **THEN** the sandbox signals the replica controller that execution is paused
- **AND** the slice execution output (instructions used so far) is returned

#### Scenario: Resume execution in sandbox
- **WHEN** a paused execution is resumed
- **THEN** the sandbox continues from where it left off
- **AND** the execution state (registers, stack, memory) is preserved in the sandbox process

#### Scenario: Abort execution in sandbox
- **WHEN** a paused execution is aborted (e.g., due to state sync)
- **THEN** the sandbox process cleans up the execution state
- **AND** the execution can be restarted from scratch in a subsequent round

#### Scenario: Out-of-instructions handling
- **WHEN** the Wasm executor detects that instructions are exhausted
- **THEN** the `OutOfInstructionsHandler` is invoked
- **AND** it either pauses execution (DTS) or returns an error (no DTS or total limit reached)
- **AND** the handler uses condition variables to synchronize between the execution thread and the controller

#### Scenario: Slice count limit
- **WHEN** a message execution has used its maximum number of slices (up to 400)
- **THEN** execution fails with an out-of-instructions error
- **AND** this provides a secondary safeguard beyond the instruction limit

### Requirement: Sandbox Memory Management

Sandbox processes manage canister memory through shared memory mappings.

#### Scenario: Memory sharing between replica and sandbox
- **WHEN** a canister's memory is needed in the sandbox
- **THEN** memory pages are shared using file-backed memory mappings
- **AND** the sandbox can read and write these pages during execution

#### Scenario: Memory serialization modes
- **WHEN** memory is passed to the sandbox
- **THEN** it can be serialized as:
  - Shared memory (most efficient for large memories)
  - Direct transfer (for small memories or when shared memory is unavailable)

#### Scenario: Default sandbox process RSS
- **WHEN** a new sandbox process is created
- **THEN** its RSS is initially estimated at 5 MiB
- **AND** the actual memory usage is updated asynchronously via OS metrics monitoring

### Requirement: Compiler Sandbox

Wasm compilation happens in a dedicated compiler sandbox process.

#### Scenario: Compiler sandbox compilation
- **WHEN** a new Wasm module needs to be compiled
- **THEN** the compilation is delegated to a dedicated compiler sandbox process
- **AND** this isolates compilation from execution
- **AND** the compiled module is stored in the compilation cache for reuse

### Requirement: Launcher Process

A launcher process manages the creation of sandbox processes.

#### Scenario: Launcher process spawning
- **WHEN** the replica needs a new sandbox process
- **THEN** it sends a request to the launcher process
- **AND** the launcher creates the sandbox process with appropriate permissions and isolation
- **AND** the launcher manages the lifecycle of child sandbox processes

### Requirement: Sandbox Process Monitoring

Sandbox processes are monitored for health and resource usage.

#### Scenario: Sandbox process update interval
- **WHEN** the sandbox monitoring timer fires (every 10 seconds)
- **THEN** OS-level metrics (RSS, CPU) for all sandbox processes are updated
- **AND** sandbox processes that have exceeded resource limits may be evicted

#### Scenario: Sandbox process crash handling
- **WHEN** a sandbox process crashes or exits unexpectedly
- **THEN** the controller detects the exit via the process status
- **AND** any ongoing execution in that sandbox fails
- **AND** a new sandbox process will be created for the next execution
