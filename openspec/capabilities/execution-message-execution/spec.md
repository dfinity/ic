# Execution: Message Execution Capability Specification

**Source narrative**: `openspec/specs/execution/message-execution.md`
**Crates**: `ic-execution-environment`
**Key files**: `rs/execution_environment/src/execution/call_or_task.rs`, `rs/execution_environment/src/execution/response.rs`

---

## REQ-MSGEXEC-001: Update Call Execution

Update calls MUST invoke canister methods that modify state, with proper call context management.

### SCENARIO-MSGEXEC-001: Ingress message execution
**Given** an ingress message targeting an update method is executed
**When** execution runs
**Then** the canister's update method is invoked with the message payload
**And** the caller principal is the ingress message sender
**And** the result is recorded in the ingress history
**And** execution cycles are prepaid and unused cycles refunded

### SCENARIO-MSGEXEC-002: Inter-canister request execution
**Given** an inter-canister request targeting an update method is executed
**When** execution runs
**Then** the canister's update method is invoked
**And** the caller principal is the sending canister's ID
**And** the result is sent back as a response to the caller

### SCENARIO-MSGEXEC-003: Call context creation
**Given** a new call begins execution
**When** the context is created
**Then** the call context tracks origin, outstanding calls, and whether a response has been sent

### SCENARIO-MSGEXEC-015: Replicated query call execution
**Given** a query method is called via an ingress or inter-canister request in replicated context
**When** execution runs
**Then** the query executes with replicated state changes
**And** the canister can reply or reject but cannot make inter-canister calls

---

## REQ-MSGEXEC-002: Response Callback Execution

When a response arrives, the appropriate callback MUST be executed.

### SCENARIO-MSGEXEC-004: Reply callback execution
**Given** a response with `Payload::Data` arrives for an outstanding call
**When** the reply callback runs
**Then** the response payload is available via `ic0.msg_arg_data_*`
**And** incoming refund cycles are available

### SCENARIO-MSGEXEC-005: Reject callback execution
**Given** a response with `Payload::Reject` arrives
**When** the reject callback runs
**Then** the reject code and message are available via `ic0.msg_reject_code` and `ic0.msg_reject_msg_*`

### SCENARIO-MSGEXEC-006: Cleanup callback after trap
**Given** a reply or reject callback traps during execution
**When** error handling runs
**Then** the cleanup callback is executed if one was registered
**And** the cleanup callback has a limited API (no calls, no replies)
**And** 5% of the total message instruction limit is reserved for cleanup execution

### SCENARIO-MSGEXEC-007: Response cycles refund
**Given** a response arrives
**When** refunding runs
**Then** cycles sent but not accepted by the callee are refunded
**And** cycles reserved for response transmission but not fully used are refunded
**And** the refund for sent cycles cannot exceed the originally sent cycles

### SCENARIO-MSGEXEC-016: Callback unregistration
**Given** a response callback finishes (including cleanup if needed)
**When** post-execution cleanup runs
**Then** the callback is unregistered from the call context
**And** if all callbacks are unregistered and a response was sent, the call context is closed
**And** unused execution cycles are refunded

### SCENARIO-MSGEXEC-017: Response callback with DTS
**Given** a response callback exceeds the slice instruction limit
**When** deterministic time slicing pauses the callback
**Then** the callback execution is paused and resumed in a subsequent round
**And** if the callback traps after resumption, the cleanup callback may also be paused
**And** the clean canister state is preserved for re-application of state changes on resume

---

## REQ-MSGEXEC-003: System Task Execution

System tasks (heartbeat, timer, on_low_wasm_memory) MUST be executed automatically.

### SCENARIO-MSGEXEC-008: Heartbeat execution
**Given** a canister exports `canister_heartbeat` and is in `Running` state
**When** the scheduler assigns heartbeat tasks
**Then** the heartbeat is executed once at the beginning of each round
**And** the canister can make inter-canister calls from the heartbeat

### SCENARIO-MSGEXEC-009: Global timer execution
**Given** a canister exports `canister_global_timer` and the timer deadline has been reached
**When** the timer fires
**Then** the timer callback is executed
**And** the global timer is deactivated after execution (must be re-armed if needed)

### SCENARIO-MSGEXEC-010: On low Wasm memory hook
**Given** a canister exports `canister_on_low_wasm_memory` and memory crosses the threshold
**When** the hook fires
**Then** the hook is executed
**And** if the canister is frozen and cannot pay, the hook status is reset to `Ready` for later retry

### SCENARIO-MSGEXEC-011: System task failure does not affect canister
**Given** a heartbeat or timer execution traps
**When** the trap occurs
**Then** the trap is logged but the canister continues to operate normally

---

## REQ-MSGEXEC-004: Inspect Message

The `canister_inspect_message` system method MUST allow canisters to filter ingress messages pre-consensus.

### SCENARIO-MSGEXEC-012: Inspect message acceptance
**Given** `canister_inspect_message` is exported and the canister calls `ic0.accept_message()`
**When** the inspect runs
**Then** the ingress message is accepted for processing

### SCENARIO-MSGEXEC-013: Inspect message rejection
**Given** `canister_inspect_message` is exported and `accept_message()` is NOT called
**When** the inspect runs
**Then** the ingress message is rejected with `CanisterRejectedMessage`

### SCENARIO-MSGEXEC-014: No inspect export accepts all
**Given** a canister does not export `canister_inspect_message`
**When** an ingress message arrives
**Then** the message is accepted by default

### SCENARIO-MSGEXEC-018: Inspect message for management canister
**Given** an ingress message is directed to the management canister (`IC_00`)
**When** ingress inspection runs
**Then** method-specific validation is performed (e.g., controller check, subnet admin check)
**And** certain methods are rejected entirely for ingress (e.g., `raw_rand`, `deposit_cycles`, `http_request`)

---

## REQ-MSGEXEC-005: Call or Task Execution Flow

The execution of calls and tasks MUST follow a common flow with cycle prepayment, metadata propagation, and validation.

### SCENARIO-MSGEXEC-019: Execution cycle prepayment
**Given** a call or task begins execution
**When** cycles are prepaid based on the message instruction limit
**Then** the prepaid cycles are deducted from the canister balance
**And** if prepayment fails (canister frozen), the message fails with `CanisterOutOfCycles`

### SCENARIO-MSGEXEC-020: Request metadata propagation
**Given** an inter-canister request triggers execution
**When** the execution context is set up
**Then** request metadata (call tree depth, call tree start time) is propagated to any downstream calls
**And** for new call trees (ingress or tasks), metadata is initialized with the current time

### SCENARIO-MSGEXEC-021: Message validation
**Given** a message arrives for execution
**When** pre-execution validation runs
**Then** the canister must be in `Running` state (not `Stopping` or `Stopped`)
**And** the canister must have a Wasm module installed
**And** the Wasm module must export the requested method

---

## REQ-MSGEXEC-006: Ingress Filtering

Ingress messages MUST be filtered before entering the execution pipeline.

### SCENARIO-MSGEXEC-022: Ingress filter service
**Given** an ingress message arrives at the replica
**When** the ingress filter service processes the message
**Then** it checks the message against the latest certified state
**And** for management canister messages, method-level permissions are checked
**And** for canister messages, `canister_inspect_message` is executed if available

### SCENARIO-MSGEXEC-023: Certified state unavailable
**Given** the ingress filter cannot obtain certified state
**When** an ingress message arrives
**Then** the message is rejected with `CertifiedStateUnavailable`

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-MSGEXEC-001 | Update call execution | narrative | rs/execution_environment/src/execution/ |
| REQ-MSGEXEC-002 | Response callback | narrative | rs/execution_environment/src/execution/response.rs |
| REQ-MSGEXEC-003 | System task execution | narrative | rs/execution_environment/tests/ |
| REQ-MSGEXEC-004 | Inspect message | narrative | rs/execution_environment/tests/ |
| REQ-MSGEXEC-005 | Call or task execution flow | narrative | rs/execution_environment/src/execution/call_or_task.rs |
| REQ-MSGEXEC-006 | Ingress filtering | narrative | rs/execution_environment/src/ |
