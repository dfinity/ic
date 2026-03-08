# System API Implementation

This specification covers the IC System API functions available to canisters during Wasm execution.

## Requirements

### Requirement: Message Operations

Canisters interact with incoming and outgoing messages via the System API.

#### Scenario: Read incoming message data
- **WHEN** a canister calls `ic0.msg_arg_data_size` and `ic0.msg_arg_data_copy`
- **THEN** the size and contents of the incoming message payload are returned
- **AND** this is available in Update, Init, ReplicatedQuery, NonReplicatedQuery, CompositeQuery, ReplyCallback, and InspectMessage contexts

#### Scenario: Get caller principal
- **WHEN** a canister calls `ic0.msg_caller_size` and `ic0.msg_caller_copy`
- **THEN** the principal ID of the message sender is returned

#### Scenario: Reply to a message
- **WHEN** a canister calls `ic0.msg_reply_data_append` followed by `ic0.msg_reply`
- **THEN** the accumulated reply data is sent as a response
- **AND** the call context is marked as replied
- **AND** calling `msg_reply` a second time in the same context traps

#### Scenario: Reject a message
- **WHEN** a canister calls `ic0.msg_reject` with a reject message
- **THEN** a reject response is sent to the caller
- **AND** the reject code is `CanisterReject`

#### Scenario: Read reject information
- **WHEN** a reject callback executes
- **THEN** `ic0.msg_reject_code` returns the reject code
- **AND** `ic0.msg_reject_msg_size` and `ic0.msg_reject_msg_copy` provide the reject message

#### Scenario: Reply size limit
- **WHEN** a canister accumulates reply data
- **THEN** for non-replicated queries, the maximum reply size is 3 MiB
- **AND** for replicated contexts, the maximum is `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`

### Requirement: Inter-Canister Calls

Canisters can make calls to other canisters.

#### Scenario: Construct a call
- **WHEN** a canister calls `ic0.call_new(callee, method, reply_fn, reply_env, reject_fn, reject_env)`
- **THEN** a new outgoing call is prepared
- **AND** the reply and reject callbacks are registered

#### Scenario: Add call data
- **WHEN** a canister calls `ic0.call_data_append(data, size)`
- **THEN** the data is appended to the outgoing call's payload

#### Scenario: Add cycles to call
- **WHEN** a canister calls `ic0.call_cycles_add128(high, low)`
- **THEN** the specified cycles are attached to the outgoing call

#### Scenario: Perform the call
- **WHEN** a canister calls `ic0.call_perform`
- **THEN** the prepared call is enqueued for delivery
- **AND** a callback is registered to handle the response
- **AND** the call context's outstanding call count increases

#### Scenario: Set cleanup callback
- **WHEN** a canister calls `ic0.call_on_cleanup(fn, env)`
- **THEN** a cleanup callback is registered for the current call
- **AND** the cleanup runs if the reply or reject callback traps

#### Scenario: Best-effort call with timeout
- **WHEN** a canister calls `ic0.call_with_best_effort_response(timeout_seconds)`
- **THEN** the call is marked as best-effort with the specified timeout
- **AND** the maximum timeout is 300 seconds

#### Scenario: Call routing
- **WHEN** a call is performed with `call_perform`
- **THEN** the destination canister is looked up in the routing table
- **AND** cross-subnet calls are routed to the appropriate subnet
- **AND** local calls are delivered directly

### Requirement: Cycles Operations

Canisters can query and manipulate their cycles balance.

#### Scenario: Query cycles balance
- **WHEN** a canister calls `ic0.canister_cycle_balance128`
- **THEN** the current cycles balance is written to the specified memory location as a 128-bit value

#### Scenario: Accept cycles from message
- **WHEN** a canister calls `ic0.msg_cycles_available128` and `ic0.msg_cycles_accept128`
- **THEN** the available cycles from the incoming message are reported
- **AND** up to the requested amount is accepted and added to the canister's balance

#### Scenario: Check cycles refund
- **WHEN** a callback executes and calls `ic0.msg_cycles_refunded128`
- **THEN** the number of cycles refunded in the response is returned

### Requirement: Canister Self-Identification

Canisters can query their own identity and status.

#### Scenario: Get own canister ID
- **WHEN** a canister calls `ic0.canister_self_size` and `ic0.canister_self_copy`
- **THEN** the canister's own principal ID is returned

#### Scenario: Get current time
- **WHEN** a canister calls `ic0.time`
- **THEN** the current IC time is returned as nanoseconds since Unix epoch

#### Scenario: Get canister version
- **WHEN** a canister calls `ic0.canister_version`
- **THEN** the canister's current version number is returned

### Requirement: Certified Data

Canisters can set data to be included in certified state.

#### Scenario: Set certified data
- **WHEN** a canister calls `ic0.certified_data_set(data, size)` during an update execution
- **THEN** the certified data is updated (max 32 bytes)
- **AND** the data will be included in the next state certification

#### Scenario: Read data certificate
- **WHEN** a canister calls `ic0.data_certificate_present` and `ic0.data_certificate_copy` during a non-replicated query
- **THEN** the state certificate containing the canister's certified data is returned

### Requirement: Global Timer

Canisters can set a global timer for periodic execution.

#### Scenario: Set global timer
- **WHEN** a canister calls `ic0.global_timer_set(timestamp)`
- **THEN** the global timer is set to fire at the specified timestamp
- **AND** the previous timer value is returned
- **AND** setting the timer to 0 deactivates it

### Requirement: Stable Memory System API

Canisters access stable memory through dedicated System API functions.

#### Scenario: 32-bit stable memory API
- **WHEN** a canister uses `ic0.stable_size`, `ic0.stable_grow`, `ic0.stable_read`, `ic0.stable_write`
- **THEN** stable memory is accessed with 32-bit page addresses (max 4 GiB)

#### Scenario: 64-bit stable memory API
- **WHEN** a canister uses `ic0.stable64_size`, `ic0.stable64_grow`, `ic0.stable64_read`, `ic0.stable64_write`
- **THEN** stable memory is accessed with 64-bit addresses (larger capacity)

### Requirement: Performance Counters

Canisters can monitor their execution performance.

#### Scenario: Instruction counter
- **WHEN** a canister calls `ic0.performance_counter(0)`
- **THEN** the number of instructions executed so far in the current message is returned

#### Scenario: Call context instruction counter
- **WHEN** a canister calls `ic0.performance_counter(1)`
- **THEN** the total instructions executed across the entire call context is returned

### Requirement: Trap and Debug

Canisters can trap and produce debug output.

#### Scenario: Explicit trap
- **WHEN** a canister calls `ic0.trap(msg, size)`
- **THEN** execution is aborted with the provided message
- **AND** all state changes from the current execution are rolled back

#### Scenario: Debug print
- **WHEN** a canister calls `ic0.debug_print(msg, size)`
- **THEN** the message is added to the canister's log

### Requirement: Accept Message (Inspect)

During inspect_message, the canister signals acceptance.

#### Scenario: Accept message
- **WHEN** `ic0.accept_message()` is called during `canister_inspect_message`
- **THEN** the ingress message is accepted for processing
- **AND** calling `accept_message` outside of inspect context traps

### Requirement: Is Controller Check

Canisters can check if a principal is one of their controllers.

#### Scenario: Check controller
- **WHEN** a canister calls `ic0.is_controller(principal, size)`
- **THEN** returns 1 if the principal is a controller, 0 otherwise

### Requirement: In Replicated Execution Check

Canisters can determine their execution context.

#### Scenario: Check replicated execution
- **WHEN** a canister calls `ic0.in_replicated_execution`
- **THEN** returns 1 if executing in replicated mode (update, heartbeat, etc.)
- **AND** returns 0 if executing in non-replicated mode (query)

### Requirement: Subnet ID Access

Canisters can query the subnet they are running on.

#### Scenario: Get subnet of canister
- **WHEN** a canister calls `ic0.subnet_self_size` and `ic0.subnet_self_copy`
- **THEN** the canister's own subnet ID is returned
