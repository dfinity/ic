# Deterministic Time Slicing (DTS)

This specification covers how long-running Wasm executions are split across multiple rounds.

## Requirements

### Requirement: DTS Overview

Deterministic Time Slicing allows canister executions that exceed the per-round slice limit to be paused and resumed across multiple consensus rounds, while maintaining determinism.

#### Scenario: DTS requires sandboxing
- **WHEN** the execution environment is initialized
- **THEN** DTS is only supported with canister sandboxing enabled
- **AND** an assertion ensures `canister_sandboxing_flag == Enabled`

#### Scenario: DTS is transparent to canisters
- **WHEN** a canister's execution is sliced across multiple rounds
- **THEN** the canister observes no difference compared to single-round execution
- **AND** the execution result is identical regardless of slice boundaries

### Requirement: Instruction Limits with DTS

DTS uses two levels of instruction limits: message-level and slice-level.

#### Scenario: Message instruction limit
- **WHEN** a message execution begins
- **THEN** the total instruction budget for the entire message is `max_instructions_per_message`
- **AND** this limit may span multiple rounds

#### Scenario: Slice instruction limit
- **WHEN** a single execution slice runs
- **THEN** it is limited to `min(max_instructions_per_slice, remaining_message_instructions)`
- **AND** the slice limit is typically much smaller than the message limit

#### Scenario: DTS is enabled check
- **WHEN** `InstructionLimits.slicing_enabled()` is called
- **THEN** it returns true if `max_slice < message`, meaning the message may be sliced

#### Scenario: Install code slice limits
- **WHEN** an `install_code` operation runs
- **THEN** it uses `max_instructions_per_install_code` as the message limit
- **AND** `max_instructions_per_install_code_slice` as the slice limit
- **AND** these are typically larger than regular message limits (e.g., 100 slices for upgrades)

### Requirement: Paused Execution State

Paused executions maintain all necessary state for deterministic resumption.

#### Scenario: Paused message execution
- **WHEN** a canister message execution is paused
- **THEN** a `PausedExecution` object is created containing:
  - The paused Wasm execution state (preserved in the sandbox process)
  - The original message context (call origin, prepaid cycles, etc.)
  - Any partial state changes accumulated so far
- **AND** the canister is marked with `NextExecution::ContinueLong`

#### Scenario: Paused install_code execution
- **WHEN** an `install_code` execution is paused
- **THEN** a `PausedInstallCodeExecution` object is created
- **AND** the install code helper with accumulated steps is preserved
- **AND** the canister is marked with `NextExecution::ContinueInstallCode`

#### Scenario: Paused execution registry
- **WHEN** executions are paused
- **THEN** they are stored in a global `PausedExecutionRegistry`
- **AND** the registry uses monotonically increasing IDs to track paused executions
- **AND** the registry stores both paused message executions and paused install_code executions separately

### Requirement: Resuming Paused Executions

Paused executions are resumed in subsequent rounds.

#### Scenario: Resume message execution
- **WHEN** a round begins and a canister has `NextExecution::ContinueLong`
- **THEN** the scheduler resumes the paused execution before processing any new messages
- **AND** the resumed execution continues from where it left off
- **AND** the remaining instruction budget from the message limit is available

#### Scenario: Resume install_code execution
- **WHEN** a round begins and a canister has `NextExecution::ContinueInstallCode`
- **THEN** the scheduler calls `advance_long_running_install_code`
- **AND** the install_code execution is resumed with a fresh slice instruction budget
- **AND** other install_code messages for the same canister remain blocked

#### Scenario: Resume with updated round context
- **WHEN** a paused execution is resumed
- **THEN** the round context (network topology, time, cost schedule) may have changed
- **AND** the execution uses the updated context for any new operations

### Requirement: Aborting Paused Executions

Paused executions can be aborted when necessary.

#### Scenario: Abort on state sync
- **WHEN** the replica switches to a new replicated state obtained via state sync
- **THEN** all paused executions from the old state are abandoned
- **AND** `exec_env.abandon_paused_executions()` clears the paused execution registry

#### Scenario: Abort returns original message
- **WHEN** a paused execution is aborted
- **THEN** the original message (or task) is returned
- **AND** the prepaid cycles for execution are returned
- **AND** the message will be re-executed from scratch in a subsequent round

### Requirement: DTS for Multi-Stage Operations

Operations like install and upgrade have multiple stages that each may be sliced.

#### Scenario: Upgrade with DTS
- **WHEN** a canister upgrade is executed with DTS
- **THEN** each stage (pre_upgrade, start, post_upgrade) may be independently paused
- **AND** the execution state machine transitions between stages:
  - `PausedPreUpgradeExecution` -> pre_upgrade completes -> create new state -> `PausedStartExecutionDuringUpgrade` -> start completes -> `PausedPostUpgradeExecution`
- **AND** each stage uses the remaining instruction budget from previous stages

#### Scenario: Install with DTS
- **WHEN** a canister install is executed with DTS
- **THEN** the `start()` and `canister_init()` stages may each be paused
- **AND** execution state machines: `PausedStartExecutionDuringInstall` -> start completes -> `PausedInitExecution`

#### Scenario: Response callback with DTS
- **WHEN** a response callback execution is sliced
- **THEN** if the response callback traps after resumption, the cleanup callback may also be sliced
- **AND** the execution transitions: `PausedResponseExecution` -> response completes (with error) -> `PausedCleanupExecution`

### Requirement: DTS Slice Counter

A secondary safeguard limits the number of execution slices.

#### Scenario: Maximum slice count
- **WHEN** an execution has been sliced across many rounds
- **THEN** the maximum number of slices is bounded (up to 400)
- **AND** the actual limit is computed as `2 * (total_instruction_limit / max_slice_instruction_limit)` clamped between 4 and 400

#### Scenario: Slice count exhaustion
- **WHEN** the slice count reaches zero
- **THEN** execution fails with an out-of-instructions error
- **AND** this prevents executions that use very few instructions per slice from running indefinitely

### Requirement: DTS Canister Blocking

While a canister has a paused execution, it cannot process other messages.

#### Scenario: Message blocking during paused execution
- **WHEN** a canister has a paused message execution
- **THEN** no new messages are scheduled for execution on that canister
- **AND** messages remain in the input queue until the paused execution completes

#### Scenario: Install_code blocking during paused execution
- **WHEN** a canister has a paused install_code execution
- **THEN** no other install_code messages targeting that canister are executed
- **AND** they are skipped in the subnet queue and retried in later rounds
