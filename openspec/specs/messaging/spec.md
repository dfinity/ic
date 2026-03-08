# Messaging Specification

**Crates**: `ic-messaging`, `ic-message`

This specification covers the Messaging subsystem (`rs/messaging/`), which implements deterministic batch processing and inter-canister message routing within and across subnets (XNet).

---

## Requirements

### Requirement: Message Routing (MessageRoutingImpl)

The message routing component receives batches from consensus, processes them through the state machine, and commits the resulting state.

#### Scenario: Deliver batch at expected height
- **WHEN** a batch arrives at the expected height
- **THEN** it is accepted and queued for processing
- **AND** the expected batch height is incremented

#### Scenario: Batch at unexpected height ignored
- **WHEN** a batch arrives at a height different from the expected height
- **THEN** the batch is ignored with status `ignored`

#### Scenario: Batch queue full
- **WHEN** the batch processing queue is full (16 batches buffered)
- **THEN** new batches are rejected with status `queue_full`

#### Scenario: Successful batch processing
- **WHEN** a batch is dequeued for processing
- **THEN** the state is loaded, the state machine executes the round, and the new state is committed
- **AND** the commit scope is `CertificationScope` appropriate for the batch

#### Scenario: Registry settings loaded per batch
- **WHEN** a batch is processed
- **THEN** the system loads current registry settings including subnet size, execution limits, and chain key configurations

---

### Requirement: State Machine Execution

The state machine executes a complete round of computation including message induction, execution, and routing.

#### Scenario: Execute round phases
- **WHEN** a batch is processed through the state machine
- **THEN** the following phases execute in order:
  1. **Induction**: XNet messages and ingress messages are inducted into canister input queues
  2. **Execution**: The scheduler executes canister messages
  3. **Message Routing**: Output messages are routed to appropriate streams
  4. **Timeout Callbacks**: Expired callbacks are timed out
  5. **Timeout Messages**: Expired messages are removed
  6. **Shed Messages**: Best-effort messages are shed if memory limits are exceeded

#### Scenario: Query stats delivery
- **WHEN** a batch is processed
- **THEN** accumulated query statistics are delivered to the replicated state for aggregation

#### Scenario: Subnet split execution
- **WHEN** a subnet split is occurring
- **THEN** a special round is executed during which no messages are inducted, executed, or routed
- **AND** only the state splitting logic runs

---

### Requirement: Stream Builder

The stream builder routes canister output messages into XNet streams destined for remote subnets.

#### Scenario: Route request to correct subnet stream
- **WHEN** a canister produces a request destined for a canister on another subnet
- **THEN** the stream builder adds the request to the outgoing stream for the destination subnet

#### Scenario: Route response to correct subnet stream
- **WHEN** a canister produces a response to a request from another subnet
- **THEN** the stream builder adds the response to the outgoing stream for the originating subnet

#### Scenario: Generate reject for canister not found
- **WHEN** a request is destined for a canister that cannot be found in any subnet
- **THEN** the stream builder generates a synthetic reject response with `CanisterNotFound`

#### Scenario: Payload too large detection
- **WHEN** a message payload exceeds MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
- **THEN** a critical error is logged and the message is handled appropriately

#### Scenario: Infinite loop detection
- **WHEN** the stream builder detects an infinite routing loop
- **THEN** a critical error is logged to prevent unbounded resource consumption

#### Scenario: Response destination not found
- **WHEN** a response cannot be routed because the destination is not found
- **THEN** a critical error is logged (responses must always be deliverable)

#### Scenario: Stream metrics reporting
- **WHEN** streams are updated
- **THEN** metrics are reported for stream message counts, byte sizes, begin indices, signal counts, and signals end per remote subnet

---

### Requirement: Stream Handler

The stream handler processes incoming XNet stream slices from remote subnets and inducts messages into local canister input queues.

#### Scenario: Induct valid XNet request
- **WHEN** an XNet request arrives from a remote subnet
- **AND** the target canister is hosted on this subnet
- **AND** the sender subnet matches the routing table
- **THEN** the request is inducted into the target canister's input queue with status `success`

#### Scenario: Induct valid XNet response
- **WHEN** an XNet response arrives from a remote subnet
- **AND** the response matches an outstanding callback
- **THEN** the response is inducted with status `success`

#### Scenario: Reject request for non-existent canister
- **WHEN** an XNet request arrives for a canister not on this subnet
- **THEN** the request is rejected and a reject signal or response is generated

#### Scenario: Sender subnet mismatch
- **WHEN** an XNet message arrives from a subnet that does not match the sender's expected subnet
- **THEN** the message is rejected
- **AND** a critical error counter is incremented

#### Scenario: Receiver subnet mismatch
- **WHEN** an XNet message arrives for a canister not on this subnet (and not migrating)
- **THEN** the message is rejected
- **AND** a critical error counter is incremented

#### Scenario: Handle canister migration
- **WHEN** an XNet message arrives during a canister migration
- **AND** the sender or receiver is in the `canister_migrations` table
- **THEN** the message is handled according to migration rules (SenderMigrated, ReceiverMigrated)

#### Scenario: Garbage collection of acknowledged messages
- **WHEN** a stream header indicates messages have been acknowledged (via signals)
- **THEN** acknowledged messages are garbage collected from the outgoing stream

#### Scenario: Garbage collection of reject signals
- **WHEN** reject signals have been processed
- **THEN** they are garbage collected from the stream

#### Scenario: Queue full handling
- **WHEN** a canister's input queue is full
- **THEN** the incoming request is rejected with a queue full error

#### Scenario: XNet message backlog tracking
- **WHEN** there is a gap between the stream header's end and the last message in the slice
- **THEN** the backlog is reported as a metric per remote subnet

---

### Requirement: Demux (Message Induction)

The demux component inducts incoming messages (both XNet and ingress) into canister input queues.

#### Scenario: Induct ingress messages
- **WHEN** a batch contains ingress messages
- **THEN** the demux inducts them into the appropriate canister input queues

#### Scenario: Induct XNet stream slices
- **WHEN** a batch contains XNet stream slices
- **THEN** the demux passes them to the stream handler for processing

---

### Requirement: Valid Set Rule (Scheduling)

The scheduling component applies the valid set rule to determine which canisters should be scheduled for execution.

#### Scenario: Schedule canisters with pending messages
- **WHEN** canisters have messages in their input queues
- **THEN** they are included in the set of canisters to be scheduled for execution

---

### Requirement: Batch Time Monotonicity

The messaging system enforces that batch times are strictly non-decreasing.

#### Scenario: Non-increasing batch time
- **WHEN** a batch arrives with a time that is not greater than the previous batch time
- **THEN** a critical error is logged (`mr_non_increasing_batch_time`)

---

### Requirement: Registry-Based Configuration

The messaging system reads configuration from the IC registry for each batch.

#### Scenario: Load subnet configuration
- **WHEN** a batch is processed
- **THEN** the system loads from the registry: subnet type, max canisters, execution settings, chain key settings, provisional whitelist, and canister allocation ranges

#### Scenario: Registry read failure
- **WHEN** the registry cannot be read
- **THEN** a critical error is logged (`mr_failed_to_read_registry_error`)

#### Scenario: Missing subnet size
- **WHEN** the subnet size cannot be determined from the registry
- **THEN** a critical error is logged (`cycles_account_manager_missing_subnet_size_error`)
