# Execution: System API Capability Specification

**Source narrative**: `openspec/specs/execution/system-api.md`
**Crates**: `ic-embedders`, `ic-execution-environment`
**Key files**: `rs/embedders/src/wasmtime_embedder/system_api.rs`, `rs/execution_environment/src/execution_environment/`

---

## REQ-SYSAPI-001: Message Operations

Canisters MUST be able to read incoming messages and send responses via System API.

### SCENARIO-SYSAPI-001: Read incoming message data
**Given** a canister calls `ic0.msg_arg_data_size` and `ic0.msg_arg_data_copy`
**When** these are called in Update, Init, ReplicatedQuery, NonReplicatedQuery, CompositeQuery, ReplyCallback, or InspectMessage contexts
**Then** the size and contents of the incoming message payload are returned

### SCENARIO-SYSAPI-002: Get caller principal
**Given** a canister calls `ic0.msg_caller_size` and `ic0.msg_caller_copy`
**When** the calls execute
**Then** the principal ID of the message sender is returned

### SCENARIO-SYSAPI-003: Reply to a message
**Given** a canister calls `ic0.msg_reply_data_append` then `ic0.msg_reply`
**When** `msg_reply` is called
**Then** the accumulated reply data is sent as a response
**And** the call context is marked as replied
**And** calling `msg_reply` a second time traps

### SCENARIO-SYSAPI-004: Reject a message
**Given** a canister calls `ic0.msg_reject` with a reject message
**When** the call executes
**Then** a reject response is sent to the caller with code `CanisterReject`

### SCENARIO-SYSAPI-005: Read reject information
**Given** a reject callback executes
**When** `ic0.msg_reject_code`, `ic0.msg_reject_msg_size`, `ic0.msg_reject_msg_copy` are called
**Then** the reject code and message from the response are returned

### SCENARIO-SYSAPI-006: Reply size limit
**Given** a canister accumulates reply data
**When** the limit is checked
**Then** for non-replicated queries, max reply is 3 MiB
**And** for replicated contexts, max is `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`

---

## REQ-SYSAPI-002: Inter-Canister Calls

Canisters MUST be able to make calls to other canisters via System API.

### SCENARIO-SYSAPI-007: Construct a call
**Given** a canister calls `ic0.call_new(callee, method, reply_fn, reply_env, reject_fn, reject_env)`
**When** the call executes
**Then** a new outgoing call is prepared with registered reply and reject callbacks

### SCENARIO-SYSAPI-008: Add call data and cycles
**Given** a canister calls `ic0.call_data_append` and `ic0.call_cycles_add128`
**When** these are called before `call_perform`
**Then** data is appended to the call payload and cycles are attached

### SCENARIO-SYSAPI-009: Perform the call
**Given** a canister calls `ic0.call_perform`
**When** the call executes
**Then** the prepared call is enqueued for delivery
**And** a callback is registered and the call context's outstanding call count increases

### SCENARIO-SYSAPI-010: Set cleanup callback
**Given** a canister calls `ic0.call_on_cleanup(fn, env)`
**When** the call executes
**Then** a cleanup callback is registered that runs if the reply/reject callback traps

### SCENARIO-SYSAPI-011: Best-effort call with timeout
**Given** a canister calls `ic0.call_with_best_effort_response(timeout_seconds)`
**When** the call executes
**Then** the call is marked as best-effort with the specified timeout (max 300 seconds)

### SCENARIO-SYSAPI-012: Call routing
**Given** a call is performed with `call_perform`
**When** routing occurs
**Then** the destination is looked up in the routing table
**And** cross-subnet calls are routed to the appropriate subnet
**And** local calls are delivered directly

---

## REQ-SYSAPI-003: Cycles Operations

Canisters MUST be able to query and manipulate their cycles balance via System API.

### SCENARIO-SYSAPI-013: Query cycles balance
**Given** a canister calls `ic0.canister_cycle_balance128`
**When** the call executes
**Then** the current cycles balance is written to memory as a 128-bit value

### SCENARIO-SYSAPI-014: Accept cycles from message
**Given** a canister calls `ic0.msg_cycles_available128` then `ic0.msg_cycles_accept128`
**When** the calls execute
**Then** up to the requested amount of cycles from the incoming message are accepted
**And** the accepted cycles are added to the canister's balance

### SCENARIO-SYSAPI-015: Check cycles refund
**Given** a callback executes and calls `ic0.msg_cycles_refunded128`
**When** the call executes
**Then** the number of cycles refunded in the response is returned

---

## REQ-SYSAPI-004: Canister Self-Identification

Canisters MUST be able to query their own identity and status.

### SCENARIO-SYSAPI-016: Get own canister ID
**Given** a canister calls `ic0.canister_self_size` and `ic0.canister_self_copy`
**When** the calls execute
**Then** the canister's own principal ID is returned

### SCENARIO-SYSAPI-017: Get current time
**Given** a canister calls `ic0.time`
**When** the call executes
**Then** the current IC time is returned as nanoseconds since Unix epoch

### SCENARIO-SYSAPI-018: Get canister version
**Given** a canister calls `ic0.canister_version`
**When** the call executes
**Then** the canister's current version number is returned

---

## REQ-SYSAPI-005: Certified Data

Canisters MUST be able to set certified data and read certificates.

### SCENARIO-SYSAPI-019: Set certified data
**Given** a canister calls `ic0.certified_data_set(data, size)` during update execution
**When** the call executes
**Then** the certified data is updated (max 32 bytes)
**And** the data will be included in the next state certification

### SCENARIO-SYSAPI-020: Read data certificate
**Given** a canister calls `ic0.data_certificate_present` and `ic0.data_certificate_copy` during non-replicated query
**When** the calls execute
**Then** the state certificate containing the canister's certified data is returned

---

## REQ-SYSAPI-006: Global Timer

Canisters MUST be able to set a global timer via System API.

### SCENARIO-SYSAPI-021: Set global timer
**Given** a canister calls `ic0.global_timer_set(timestamp)`
**When** the call executes
**Then** the global timer is set to fire at the specified timestamp
**And** the previous timer value is returned
**And** setting the timer to 0 deactivates it

---

## REQ-SYSAPI-007: Stable Memory System API

Canisters MUST access stable memory through dedicated System API functions.

### SCENARIO-SYSAPI-022: 32-bit stable memory API
**Given** a canister uses `ic0.stable_size`, `ic0.stable_grow`, `ic0.stable_read`, `ic0.stable_write`
**When** these execute
**Then** stable memory is accessed with 32-bit page addresses (max 4 GiB)

### SCENARIO-SYSAPI-023: 64-bit stable memory API
**Given** a canister uses `ic0.stable64_size`, `ic0.stable64_grow`, `ic0.stable64_read`, `ic0.stable64_write`
**When** these execute
**Then** stable memory is accessed with 64-bit addresses (larger capacity)

---

## REQ-SYSAPI-008: Performance Counters

Canisters MUST be able to monitor execution performance via System API.

### SCENARIO-SYSAPI-024: Instruction counter
**Given** a canister calls `ic0.performance_counter(0)`
**When** the call executes
**Then** the number of instructions executed in the current message is returned

### SCENARIO-SYSAPI-025: Call context instruction counter
**Given** a canister calls `ic0.performance_counter(1)`
**When** the call executes
**Then** the total instructions executed across the entire call context is returned

---

## REQ-SYSAPI-009: Trap and Debug

Canisters MUST be able to explicitly trap and produce debug output.

### SCENARIO-SYSAPI-026: Explicit trap
**Given** a canister calls `ic0.trap(msg, size)`
**When** the call executes
**Then** execution is aborted with the provided message
**And** all state changes from the current execution are rolled back

### SCENARIO-SYSAPI-027: Debug print
**Given** a canister calls `ic0.debug_print(msg, size)`
**When** the call executes
**Then** the message is added to the canister's log

---

## REQ-SYSAPI-010: Inspect Message Acceptance

During `canister_inspect_message`, the canister MUST signal acceptance via System API.

### SCENARIO-SYSAPI-028: Accept message
**Given** `ic0.accept_message()` is called during `canister_inspect_message`
**When** the call executes
**Then** the ingress message is accepted for processing
**And** calling `accept_message` outside of inspect context traps

---

## REQ-SYSAPI-011: Controller Check

Canisters MUST be able to check if a principal is a controller.

### SCENARIO-SYSAPI-029: Check controller
**Given** a canister calls `ic0.is_controller(principal, size)`
**When** the call executes
**Then** returns 1 if the principal is a controller, 0 otherwise

---

## REQ-SYSAPI-012: Replicated Execution Check

Canisters MUST be able to determine their execution context.

### SCENARIO-SYSAPI-030: Check replicated execution
**Given** a canister calls `ic0.in_replicated_execution`
**When** the call executes
**Then** returns 1 if executing in replicated mode (update, heartbeat, etc.)
**And** returns 0 if executing in non-replicated mode (query)

---

## REQ-SYSAPI-013: Subnet ID Access

Canisters MUST be able to query their subnet ID.

### SCENARIO-SYSAPI-031: Get own subnet ID
**Given** a canister calls `ic0.subnet_self_size` and `ic0.subnet_self_copy`
**When** the calls execute
**Then** the canister's own subnet ID is returned

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SYSAPI-001 | Message operations | narrative | rs/embedders/tests/ |
| REQ-SYSAPI-002 | Inter-canister calls | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-003 | Cycles operations | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-004 | Self-identification | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-005 | Certified data | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-006 | Global timer | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-007 | Stable memory API | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-008 | Performance counters | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-009 | Trap and debug | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-010 | Inspect acceptance | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-011 | Controller check | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-012 | Replicated exec check | narrative | rs/execution_environment/tests/ |
| REQ-SYSAPI-013 | Subnet ID access | narrative | rs/execution_environment/tests/ |
