# Execution: Canister Sandboxing Capability Specification

**Source narrative**: `openspec/specs/execution/canister-sandboxing.md`
**Crates**: `ic-canister-sandbox-backend-lib`
**Key files**: `rs/canister_sandbox/src/`, `rs/embedders/src/wasm_executor.rs`

---

## REQ-SAND-001: Sandbox Architecture

Canister Wasm code MUST execute in separate sandbox processes for isolation and security.

### SCENARIO-SAND-001: Sandbox process creation
**Given** a canister needs to execute for the first time (or its sandbox was evicted)
**When** the execution begins
**Then** a new sandbox process is created via the launcher process
**And** the sandbox is initialized with the compiled Wasm module
**And** communication uses RPC over Unix domain sockets

### SCENARIO-SAND-002: Sandbox process reuse
**Given** a canister has an existing sandbox process from a previous execution
**When** the next execution begins
**Then** the existing sandbox process is reused
**And** this avoids process creation and module loading overhead

### SCENARIO-SAND-003: Sandbox process eviction
**Given** sandbox processes exceed resource limits or system memory is low
**When** eviction runs
**Then** least-recently-used sandbox processes are evicted
**And** eviction happens in batches (200 processes or 1 GiB of RSS at a time)
**And** memory-based eviction is triggered when available system memory falls below 250 GiB

---

## REQ-SAND-002: Sandboxed Execution Controller

The `SandboxedExecutionController` MUST manage sandbox process lifecycles and cache lookups.

### SCENARIO-SAND-004: Compilation cache lookup order
**Given** a canister execution begins
**When** the controller checks for compiled modules
**Then** it checks in order: embedder cache (process-local, fastest) → compilation cache (shared) → full compilation (cache miss)
**And** metrics are recorded for each cache level hit/miss

### SCENARIO-SAND-005: Sandbox execution input preparation
**Given** a canister execution is dispatched to a sandbox
**When** the input is prepared
**Then** it includes: function reference, system API type and parameters, canister memory state (shared memory), execution parameters (instruction limits)

### SCENARIO-SAND-006: Sandbox execution output processing
**Given** a sandbox execution completes
**When** the output is processed
**Then** it includes: Wasm execution output (instructions used, trap info), state modifications (new calls, system state changes), dirty page lists for heap and stable memory, updated exported globals

---

## REQ-SAND-003: DTS in Sandbox

Sandboxed execution MUST support Deterministic Time Slicing (pause and resume).

### SCENARIO-SAND-007: Slice execution pause in sandbox
**Given** a Wasm execution reaches the slice instruction limit in the sandbox
**When** the limit is hit
**Then** the sandbox signals the replica controller that execution is paused
**And** the slice execution output (instructions used so far) is returned

### SCENARIO-SAND-008: Resume paused execution in sandbox
**Given** a paused execution is resumed
**When** resumption runs
**Then** the sandbox continues from where it left off
**And** the execution state (registers, stack, memory) is preserved in the sandbox process

### SCENARIO-SAND-009: Abort paused execution in sandbox
**Given** a paused execution is aborted (e.g., due to state sync)
**When** the abort runs
**Then** the sandbox process cleans up the execution state
**And** the execution can be restarted from scratch in a subsequent round

### SCENARIO-SAND-010: Out-of-instructions handling
**Given** the Wasm executor detects instructions are exhausted
**When** `OutOfInstructionsHandler` is invoked
**Then** it either pauses execution (if DTS enabled and slice limit) or returns an error (if total limit reached or DTS disabled)

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SAND-001 | Sandbox architecture | linked | rs/canister_sandbox/src/dts/tests.rs |
| REQ-SAND-002 | Execution controller | narrative | rs/canister_sandbox/src/ |
| REQ-SAND-003 | DTS in sandbox | linked | rs/canister_sandbox/src/dts/tests.rs |
