# Message Execution

This specification covers how different types of messages (ingress, inter-canister, responses) are executed.

## Requirements

### Requirement: Update Call Execution

Update calls are the primary way to invoke canister methods that modify state.

#### Scenario: Ingress message execution
- **WHEN** an ingress message targeting an update method is executed
- **THEN** the canister's update method is invoked with the message payload
- **AND** the caller principal is the ingress message sender
- **AND** the result (reply or reject) is recorded in the ingress history
- **AND** execution cycles are prepaid and unused cycles are refunded

#### Scenario: Inter-canister request execution
- **WHEN** an inter-canister request targeting an update method is executed
- **THEN** the canister's update method is invoked with the request payload
- **AND** the caller principal is the sending canister's ID
- **AND** the result (reply or reject) is sent back as a response to the caller

#### Scenario: Call context creation
- **WHEN** a new call begins execution
- **THEN** a new call context is created
- **AND** the call context tracks the origin, outstanding calls, and whether a response has been sent

#### Scenario: Replicated query call execution
- **WHEN** a query method is called via an ingress or inter-canister request (replicated context)
- **THEN** the query executes with replicated state changes
- **AND** the canister can reply or reject but cannot make inter-canister calls

### Requirement: Response Callback Execution

When a response to an inter-canister call arrives, the appropriate callback is executed.

#### Scenario: Reply callback execution
- **WHEN** a response with `Payload::Data` arrives for an outstanding call
- **THEN** the reply callback registered during `call_perform` is executed
- **AND** the response payload is available via `ic0.msg_arg_data_*`
- **AND** incoming refund cycles are available

#### Scenario: Reject callback execution
- **WHEN** a response with `Payload::Reject` arrives for an outstanding call
- **THEN** the reject callback registered during `call_perform` is executed
- **AND** the reject code and message are available via `ic0.msg_reject_code` and `ic0.msg_reject_msg_*`

#### Scenario: Cleanup callback after trap
- **WHEN** a reply or reject callback traps during execution
- **THEN** the cleanup callback is executed if one was registered
- **AND** the cleanup callback has a limited API (no calls, no replies)
- **AND** 5% of the total message instruction limit is reserved for cleanup execution

#### Scenario: Response cycles refund
- **WHEN** a response arrives
- **THEN** cycles that were sent but not accepted by the callee are refunded to the caller
- **AND** cycles reserved for response transmission but not fully used are refunded
- **AND** the refund for sent cycles cannot exceed the originally sent cycles

#### Scenario: Callback unregistration
- **WHEN** a response callback finishes (including cleanup if needed)
- **THEN** the callback is unregistered from the call context
- **AND** if all callbacks are unregistered and a response was sent, the call context is closed
- **AND** unused execution cycles are refunded

#### Scenario: Response with DTS
- **WHEN** a response callback exceeds the slice instruction limit
- **THEN** the callback execution is paused
- **AND** if the callback traps after resumption, the cleanup callback may also be paused
- **AND** the clean canister state is preserved for re-application of state changes on resume

### Requirement: System Task Execution

System tasks (heartbeat, global timer, on_low_wasm_memory) are executed automatically by the scheduler.

#### Scenario: Heartbeat execution
- **WHEN** a canister exports `canister_heartbeat` and is in `Running` state
- **THEN** the heartbeat is executed once at the beginning of each round
- **AND** heartbeat execution uses the SystemTask API type
- **AND** the canister can make inter-canister calls from the heartbeat

#### Scenario: Global timer execution
- **WHEN** a canister exports `canister_global_timer` and the timer deadline has been reached
- **THEN** the timer callback is executed
- **AND** the global timer is deactivated after execution (the canister must re-arm it if needed)

#### Scenario: On low Wasm memory hook
- **WHEN** a canister exports `canister_on_low_wasm_memory` and Wasm memory usage crosses the threshold
- **THEN** the on_low_wasm_memory hook is executed
- **AND** if the canister is frozen and cannot pay for execution, the hook status is reset to `Ready` for later retry

#### Scenario: System task failure
- **WHEN** a heartbeat or global timer execution traps
- **THEN** the trap is logged but does not affect the canister's ability to receive other messages
- **AND** the canister continues to operate normally

### Requirement: Call or Task Execution Flow

The execution of calls and tasks follows a common flow.

#### Scenario: Execution cycle prepayment
- **WHEN** a call or task begins execution
- **THEN** execution cycles are prepaid based on the message instruction limit
- **AND** if prepayment fails (canister frozen), the message fails with `CanisterOutOfCycles`

#### Scenario: Request metadata propagation
- **WHEN** an inter-canister request triggers execution
- **THEN** request metadata (call tree depth, call tree start time) is propagated to any downstream calls
- **AND** for new call trees (ingress or tasks), metadata is initialized with the current time

#### Scenario: Message validation
- **WHEN** a message arrives for execution
- **THEN** the canister must be in `Running` state (not `Stopping` or `Stopped`)
- **AND** the canister must have a Wasm module installed
- **AND** the Wasm module must export the requested method

### Requirement: Inspect Message

The `canister_inspect_message` system method allows canisters to filter incoming ingress messages pre-consensus.

#### Scenario: Inspect message acceptance
- **WHEN** `canister_inspect_message` is exported and executes without trapping
- **AND** the canister calls `ic0.accept_message()`
- **THEN** the ingress message is accepted for processing

#### Scenario: Inspect message rejection
- **WHEN** `canister_inspect_message` is exported and the canister does not call `ic0.accept_message()`
- **THEN** the ingress message is rejected with `CanisterRejectedMessage`

#### Scenario: No inspect message export
- **WHEN** a canister does not export `canister_inspect_message`
- **THEN** all ingress messages are accepted by default (inspect is a no-op)

#### Scenario: Inspect message for management canister
- **WHEN** an ingress message is directed to the management canister (`IC_00`)
- **THEN** method-specific validation is performed (e.g., controller check, subnet admin check)
- **AND** certain methods are rejected entirely for ingress (e.g., `raw_rand`, `deposit_cycles`, `http_request`)

### Requirement: Ingress Filtering

Ingress messages are filtered before entering the execution pipeline.

#### Scenario: Ingress filter service
- **WHEN** an ingress message arrives at the replica
- **THEN** the ingress filter service checks the message against the latest certified state
- **AND** for management canister messages, method-level permissions are checked
- **AND** for canister messages, `canister_inspect_message` is executed if available

#### Scenario: Certified state unavailable
- **WHEN** the ingress filter cannot obtain certified state
- **THEN** the ingress message is rejected with `CertifiedStateUnavailable`
