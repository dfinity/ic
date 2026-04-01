# Execution: Deterministic Time Slicing (DTS) Capability Specification

**Source narrative**: `openspec/specs/execution/deterministic-time-slicing.md`
**Crates**: `ic-execution-environment`, `ic-embedders`
**Key files**: `rs/execution_environment/src/execution/`, `rs/embedders/src/wasm_executor.rs`

---

## REQ-DTS-001: DTS Overview and Transparency

DTS MUST allow long-running Wasm executions to be paused and resumed across multiple consensus rounds while remaining fully transparent to canisters.

### SCENARIO-DTS-001: DTS requires sandboxing
**Given** the execution environment is initialized
**When** DTS is configured
**Then** DTS is only supported with canister sandboxing enabled
**And** an assertion ensures `canister_sandboxing_flag == Enabled`

### SCENARIO-DTS-002: DTS is transparent to canisters
**Given** a canister's execution is sliced across multiple rounds
**When** the canister observes its execution
**Then** the result is identical to single-round execution
**And** the canister detects no difference in observable behavior

---

## REQ-DTS-002: Instruction Limits

DTS MUST use two-level instruction limits: message-level (total) and slice-level (per round).

### SCENARIO-DTS-003: Message instruction limit
**Given** a message execution begins
**When** the total budget is set
**Then** it equals `max_instructions_per_message` across all rounds

### SCENARIO-DTS-004: Slice instruction limit
**Given** a single execution slice runs
**When** the slice limit is applied
**Then** it equals `min(max_instructions_per_slice, remaining_message_instructions)`

### SCENARIO-DTS-005: Slicing enabled check
**Given** `InstructionLimits.slicing_enabled()` is called
**When** the check executes
**Then** it returns true if `max_slice < message` (message may be sliced)

### SCENARIO-DTS-006: Install code slice limits
**Given** an `install_code` operation runs
**When** instruction limits are applied
**Then** it uses `max_instructions_per_install_code` as the message limit
**And** `max_instructions_per_install_code_slice` as the slice limit
**And** these are typically larger than regular message limits

---

## REQ-DTS-003: Paused Execution State

Paused executions MUST preserve all state necessary for deterministic resumption.

### SCENARIO-DTS-007: Paused message execution state
**Given** a canister message execution is paused
**When** the pause is recorded
**Then** a `PausedExecution` object is created containing: paused Wasm state, original message context, prepaid cycles, partial state changes
**And** the canister is marked `NextExecution::ContinueLong`

### SCENARIO-DTS-008: Paused install_code execution state
**Given** an `install_code` execution is paused
**When** the pause is recorded
**Then** a `PausedInstallCodeExecution` object is created with accumulated install steps
**And** the canister is marked `NextExecution::ContinueInstallCode`

### SCENARIO-DTS-009: Paused execution registry
**Given** executions are paused
**When** they are stored
**Then** they are stored in a global `PausedExecutionRegistry` with monotonically increasing IDs
**And** the registry tracks paused message executions and paused install_code executions separately

---

## REQ-DTS-004: Resuming Paused Executions

The scheduler MUST resume paused executions in subsequent rounds.

### SCENARIO-DTS-010: Resume paused message execution
**Given** a round begins and a canister has `NextExecution::ContinueLong`
**When** the scheduler processes canisters
**Then** the paused execution is resumed before processing new messages
**And** execution continues from where it left off with remaining instruction budget

### SCENARIO-DTS-011: Resume paused install_code
**Given** a round begins and a canister has `NextExecution::ContinueInstallCode`
**When** the scheduler runs `advance_long_running_install_code`
**Then** the install_code execution is resumed with a fresh slice instruction budget
**And** other install_code messages for the same canister remain blocked

### SCENARIO-DTS-012: Resume with updated round context
**Given** a paused execution is resumed in a later round
**When** the round context has changed (topology, time, cost schedule)
**Then** the execution uses the updated context for any new operations

---

## REQ-DTS-005: Aborting Paused Executions

Paused executions MUST be abortable when the replicated state is replaced.

### SCENARIO-DTS-013: Abort on state sync
**Given** the replica switches to a new replicated state via state sync
**When** the old state is abandoned
**Then** `exec_env.abandon_paused_executions()` clears the paused execution registry
**And** all paused executions from the old state are abandoned

### SCENARIO-DTS-014: Abort returns original message
**Given** a paused execution is aborted
**When** the abort completes
**Then** the original message (or task) is returned
**And** prepaid cycles for execution are returned
**And** the message will be re-executed from scratch in a subsequent round

---

## REQ-DTS-006: Multi-Stage DTS Operations

Install and upgrade operations MUST support DTS across multiple stages.

### SCENARIO-DTS-015: Upgrade with DTS across stages
**Given** a canister upgrade is executed with DTS
**When** execution proceeds
**Then** each stage (pre_upgrade, start, post_upgrade) may be independently paused
**And** state machine transitions: `PausedPreUpgradeExecution` → `PausedStartExecutionDuringUpgrade` → `PausedPostUpgradeExecution`
**And** each stage uses remaining instruction budget from prior stages

### SCENARIO-DTS-016: Install with DTS across stages
**Given** a canister install is executed with DTS
**When** execution proceeds
**Then** `start()` and `canister_init()` stages may each be paused
**And** state machine transitions: `PausedStartExecutionDuringInstall` → `PausedInitExecution`

### SCENARIO-DTS-017: Response callback with DTS
**Given** a response callback execution is sliced
**When** the callback traps after resumption
**Then** the cleanup callback may also be sliced
**And** state machine transitions: `PausedResponseExecution` → `PausedCleanupExecution`

---

## REQ-DTS-007: DTS Slice Counter

A secondary slice count safeguard MUST prevent indefinitely-sliced executions.

### SCENARIO-DTS-018: Maximum slice count
**Given** an execution has been sliced across many rounds
**When** the slice count is computed
**Then** the maximum is `2 * (total_instruction_limit / max_slice_instruction_limit)` clamped between 4 and 400

### SCENARIO-DTS-019: Slice count exhaustion
**Given** the slice count reaches zero
**When** the next slice begins
**Then** execution fails with an out-of-instructions error
**And** this prevents executions using very few instructions per slice from running indefinitely

---

## REQ-DTS-008: DTS Canister Blocking

While a canister has a paused execution, it MUST NOT process other messages.

### SCENARIO-DTS-020: Message blocking during paused execution
**Given** a canister has a paused message execution
**When** new messages arrive
**Then** no new messages are scheduled for execution on that canister
**And** messages remain in the input queue until the paused execution completes

### SCENARIO-DTS-021: Install_code blocking during paused execution
**Given** a canister has a paused install_code execution
**When** other install_code messages arrive for the same canister
**Then** they are skipped in the subnet queue and retried in later rounds

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-DTS-001 | DTS overview/transparency | narrative | execution_test.rs |
| REQ-DTS-002 | Instruction limits | narrative | execution_test.rs |
| REQ-DTS-003 | Paused execution state | narrative | execution_test.rs |
| REQ-DTS-004 | Resuming paused | narrative | execution_test.rs |
| REQ-DTS-005 | Aborting paused | narrative | execution_test.rs |
| REQ-DTS-006 | Multi-stage DTS | narrative | execution_test.rs |
| REQ-DTS-007 | Slice counter | narrative | execution_test.rs |
| REQ-DTS-008 | Canister blocking | narrative | execution_test.rs |
