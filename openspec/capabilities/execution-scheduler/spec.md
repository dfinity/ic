# Execution Scheduler Capability Specification

**Source narrative**: `openspec/specs/execution/scheduler.md`
**Crates**: `ic-execution-environment` (scheduler module)
**Key files**:
- `rs/execution_environment/src/scheduler.rs`
- `rs/execution_environment/src/scheduler/tests/`

---

## REQ-SCHED-001: Execution Round Structure

Each execution round MUST process subnet messages and canister messages within instruction budgets, executing phases in a defined order.

### SCENARIO-SCHED-001: Round execution phases
**Given** an execution round begins
**When** the scheduler drives a round
**Then** the following phases execute in order:
1. Round preparation: initialize round limits, purge expired ingress, set CSPRNG
2. Consensus queue draining: process all responses (no instruction limit)
3. Heap delta check: skip remaining execution if heap delta exceeds scheduled limit
4. Postponed raw_rand execution: process postponed raw_rand messages
5. Long-running install_code advancement: resume paused install_code executions
6. Inner round: iteratively execute subnet and canister messages
7. Round finalization: charge idle canisters, update metrics, GC

### SCENARIO-SCHED-002: Round instruction budget
**Given** a round is initialized
**When** the round instruction budget is computed
**Then** the initial budget = `max_instructions_per_round - max(max_instructions_per_slice, max_instructions_per_install_code_slice) + 1`
**And** this accounts for worst-case overshoot by a single slice

### SCENARIO-SCHED-003: Subnet messages instruction budget
**Given** subnet messages are being executed
**When** the subnet message budget is computed
**Then** it equals `max_instructions_per_round / 16`
**And** this prevents subnet messages from consuming the entire round budget

---

## REQ-SCHED-002: Inner Round Iterations

The inner round MUST execute multiple iterations until the budget is exhausted or no progress can be made.

### SCENARIO-SCHED-004: Inner round iteration steps
**Given** an inner round iteration begins
**When** the iteration executes
**Then** the following steps occur in order:
1. Drain subnet queues (management canister messages)
2. On first iteration only: add heartbeat and global timer tasks
3. Partition canisters across execution threads per round schedule
4. Execute canisters in parallel on thread pool
5. Induct messages (move outputs to inputs, same subnet)
**And** repeat until budget exhausted or no progress

### SCENARIO-SCHED-005: Canister execution on threads
**Given** canisters are assigned to execution threads
**When** a thread processes its assigned canisters
**Then** each thread processes canisters sequentially
**And** each canister executes one message per iteration
**And** round limits are shared across threads and updated after each canister completes

---

## REQ-SCHED-003: Round Schedule and Canister Ordering

Canisters MUST be ordered for execution based on accumulated priority and compute allocation.

### SCENARIO-SCHED-006: Priority-based scheduling
**Given** canisters are ordered for execution
**When** the round schedule is built
**Then** canisters with higher accumulated priority are scheduled first
**And** accumulated priority increases proportionally to compute allocation
**And** accumulated priority decreases after execution

### SCENARIO-SCHED-007: Heartbeat and global timer tasks
**Given** the first inner round iteration begins
**When** tasks are assigned to eligible canisters
**Then** heartbeat tasks are added for running canisters exporting `canister_heartbeat`
**And** global timer tasks are added for running canisters exporting `canister_global_timer` with elapsed deadlines
**And** canisters with long-running executions do NOT receive heartbeat/timer tasks

### SCENARIO-SCHED-008: Rate limiting by heap delta
**Given** `rate_limiting_of_heap_delta` is enabled
**When** a canister has accumulated too much heap delta
**Then** that canister is deprioritized (filtered out from active scheduling)

### SCENARIO-SCHED-009: Rate limiting by instructions
**Given** `rate_limiting_of_instructions` is enabled
**When** a canister has executed too many instructions recently
**Then** that canister is deprioritized in the round schedule

---

## REQ-SCHED-004: Long-Running Executions (DTS)

The scheduler MUST support executions that span multiple rounds via Deterministic Time Slicing.

### SCENARIO-SCHED-010: Long-running install_code
**Given** an `install_code` execution is paused mid-execution
**When** the scheduler processes the canister
**Then** the canister is marked `NextExecution::ContinueInstallCode`
**And** subsequent rounds resume the paused execution before processing other messages
**And** no other messages execute on that canister until install_code completes

### SCENARIO-SCHED-011: Long-running canister message
**Given** a canister message execution is paused mid-execution
**When** the scheduler processes the canister in subsequent rounds
**Then** the canister is marked `NextExecution::ContinueLong`
**And** the paused execution is resumed
**And** no new messages execute on that canister until the current one completes

### SCENARIO-SCHED-012: Aborting paused executions on state sync
**Given** a state sync replaces the replicated state
**When** the old state is abandoned
**Then** all paused executions in the old state are abandoned
**And** aborted long-running executions restart from scratch in the next round

---

## REQ-SCHED-005: Subnet Message Execution

The scheduler MUST route management canister messages to the appropriate ExecutionEnvironment handlers.

### SCENARIO-SCHED-013: Subnet message routing
**Given** a message addressed to the management canister (`ic:00`) arrives
**When** the scheduler drains the subnet queue
**Then** the message is routed by method name to the appropriate handler (create_canister, install_code, update_settings, etc.)

### SCENARIO-SCHED-014: Subnet message blocking by long-running install_code
**Given** a subnet message targets a canister with an active long-running install_code
**When** the scheduler processes subnet messages
**Then** the message is skipped and remains in the queue
**And** it will be processed once the install_code completes

---

## REQ-SCHED-006: Same-Subnet Message Induction

After each iteration, output messages MUST be inducted as inputs for same-subnet destinations.

### SCENARIO-SCHED-015: Same-subnet message induction
**Given** canister A sends a message to canister B on the same subnet during an iteration
**When** the iteration completes
**Then** A's output message is moved to B's input queue
**And** B can process it in the next iteration of the same round

---

## REQ-SCHED-007: Heap Delta Management

The scheduler MUST track and limit heap delta to ensure checkpointing keeps up.

### SCENARIO-SCHED-016: Heap delta accumulation
**Given** a canister execution modifies heap or stable memory pages
**When** the execution completes
**Then** the canister's heap delta increases by the number of modified pages
**And** the total subnet heap delta estimate is updated

### SCENARIO-SCHED-017: Heap delta rate limiting
**Given** the subnet heap delta estimate exceeds the scheduled limit for the round
**When** the scheduler begins an inner round
**Then** no canister messages are executed
**And** only consensus queue responses are processed
**And** this prevents the checkpoint process from falling behind

### SCENARIO-SCHED-018: Scheduled heap delta limit per round
**Given** the heap delta limit for a round is computed
**When** determining the round's heap delta capacity
**Then** the limit depends on the round number within the current epoch
**And** an initial reserve is maintained for the first rounds after a checkpoint
**And** remaining capacity is distributed evenly across remaining rounds in the epoch

---

## REQ-SCHED-008: Ingress Message Lifecycle

The scheduler MUST manage ingress message expiry and deduplication.

### SCENARIO-SCHED-019: Ingress message expiry
**Given** an ingress message's expiry time has passed
**When** round preparation purges expired messages
**Then** the message is removed from the canister's input queue
**And** its ingress status is set to `Failed` with `IngressMessageTimeout`

### SCENARIO-SCHED-020: Ingress message deduplication
**Given** a duplicate ingress message is submitted (same message ID already in queue or processed)
**When** the duplicate arrives
**Then** it is rejected without being added to any queue

---

## REQ-SCHED-009: Idle Canister Charging

Canisters MUST be charged for resource usage even when not executing.

### SCENARIO-SCHED-021: Idle canister resource charging
**Given** an inner round iteration completes
**When** canisters that did not execute are charged
**Then** each idle canister is charged for storage and compute allocation
**And** the charge covers the elapsed time since the last charge
**And** canisters that exhaust their cycles may be frozen

---

## Traceability

| ID | Requirement | Status | Test File(s) |
|----|-------------|--------|-------------|
| REQ-SCHED-001 | Round structure | narrative | rs/execution_environment/src/scheduler/tests/ |
| REQ-SCHED-002 | Inner round iterations | narrative | rs/execution_environment/src/scheduler/tests/scheduling.rs |
| REQ-SCHED-003 | Canister ordering | narrative | rs/execution_environment/src/scheduler/tests/scheduling.rs |
| REQ-SCHED-004 | Long-running (DTS) | narrative | rs/execution_environment/tests/execution_test.rs |
| REQ-SCHED-005 | Subnet messages | narrative | rs/execution_environment/src/scheduler/tests/ |
| REQ-SCHED-006 | Message induction | narrative | rs/messaging/tests/messaging.rs |
| REQ-SCHED-007 | Heap delta | narrative | rs/execution_environment/src/scheduler/tests/ |
| REQ-SCHED-008 | Ingress lifecycle | narrative | rs/execution_environment/src/scheduler/tests/ |
| REQ-SCHED-009 | Idle charging | narrative | rs/execution_environment/src/scheduler/tests/ |

Status legend: `narrative` = spec exists, no REQ-* linked in tests yet | `linked` = tests reference REQ-ID | `verified` = evaluator confirmed
