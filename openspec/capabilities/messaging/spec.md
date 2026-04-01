# Messaging Capability Specification

**Source narrative**: `openspec/specs/messaging/spec.md`
**Crates**: `ic-messaging`, `ic-message`
**Key files**: `rs/messaging/src/message_routing.rs`, `rs/messaging/src/routing/`, `rs/messaging/tests/messaging.rs`

---

## REQ-MSG-001: Batch Processing (MessageRouting)

The message routing component MUST receive batches from consensus, process them, and commit resulting state.

### SCENARIO-MSG-001: Deliver batch at expected height
**Given** a batch arrives at the expected height
**When** the batch is received
**Then** it is accepted and queued for processing
**And** the expected batch height is incremented

### SCENARIO-MSG-002: Batch at unexpected height ignored
**Given** a batch arrives at a height different from the expected height
**When** the batch is received
**Then** the batch is ignored with status `ignored`

### SCENARIO-MSG-003: Batch queue full
**Given** the batch processing queue is full (16 batches buffered)
**When** a new batch arrives
**Then** the new batch is rejected with status `queue_full`

### SCENARIO-MSG-004: Successful batch processing
**Given** a batch is dequeued for processing
**When** processing runs
**Then** the state is loaded, the state machine executes the round, and the new state is committed
**And** the commit uses `CertificationScope` appropriate for the batch

### SCENARIO-MSG-005: Registry settings loaded per batch
**Given** a batch is processed
**When** registry settings are loaded
**Then** current settings are loaded including subnet size, execution limits, and chain key configurations

---

## REQ-MSG-002: State Machine Round Execution

The state machine MUST execute a complete round including induction, execution, and routing phases.

### SCENARIO-MSG-006: Execute round phases in order
**Given** a batch is processed through the state machine
**When** the round executes
**Then** phases execute in order:
  1. Induction: XNet and ingress messages inducted into canister input queues
  2. Execution: scheduler executes canister messages
  3. Message Routing: output messages routed to appropriate streams
  4. Timeout Callbacks: expired callbacks timed out
  5. Timeout Messages: expired messages removed
  6. Shed Messages: best-effort messages shed if memory limits exceeded

### SCENARIO-MSG-007: Query stats delivery
**Given** a batch is processed
**When** accumulated query statistics are delivered
**Then** they are passed to the replicated state for aggregation

### SCENARIO-MSG-008: Subnet split execution
**Given** a subnet split is occurring
**When** the special split round executes
**Then** no messages are inducted, executed, or routed
**And** only the state splitting logic runs

---

## REQ-MSG-003: Stream Builder (XNet Output Routing)

The stream builder MUST route canister output messages into XNet streams for remote subnets.

### SCENARIO-MSG-009: Route request to correct subnet stream
**Given** a canister produces a request destined for a canister on another subnet
**When** the stream builder processes the output
**Then** the request is added to the outgoing stream for the destination subnet

### SCENARIO-MSG-010: Route response to correct subnet stream
**Given** a canister produces a response to a request from another subnet
**When** the stream builder processes the output
**Then** the response is added to the outgoing stream for the originating subnet

### SCENARIO-MSG-011: Generate reject for canister not found
**Given** a request is destined for a canister not found in any subnet
**When** the stream builder processes the request
**Then** a synthetic reject response with `CanisterNotFound` is generated

### SCENARIO-MSG-012: Infinite loop detection
**Given** the stream builder detects an infinite routing loop
**When** the loop is detected
**Then** a critical error is logged to prevent unbounded resource consumption

---

## REQ-MSG-004: Stream Handler (XNet Input Processing)

The stream handler MUST process incoming XNet stream slices and induct messages into local queues.

### SCENARIO-MSG-013: Induct valid XNet request
**Given** an XNet request arrives from a remote subnet for a local canister
**And** the sender subnet matches the routing table
**When** the request is processed
**Then** the request is inducted into the target canister's input queue with status `success`

### SCENARIO-MSG-014: Induct valid XNet response
**Given** an XNet response arrives from a remote subnet matching an outstanding callback
**When** the response is processed
**Then** the response is inducted with status `success`

### SCENARIO-MSG-015: Reject request for non-local canister
**Given** an XNet request arrives for a canister not on this subnet
**When** the request is processed
**Then** the request is rejected and a reject signal or response is generated

### SCENARIO-MSG-016: Sender subnet mismatch
**Given** an XNet message arrives from a subnet that does not match the sender's expected subnet
**When** the message is processed
**Then** the message is rejected and a critical error counter is incremented

### SCENARIO-MSG-017: Handle canister migration
**Given** an XNet message arrives during a canister migration
**And** the sender or receiver is in the `canister_migrations` table
**When** the message is processed
**Then** it is handled according to migration rules (SenderMigrated, ReceiverMigrated)

### SCENARIO-MSG-018: Garbage collect acknowledged messages
**Given** a stream header indicates messages have been acknowledged via signals
**When** GC runs
**Then** acknowledged messages are removed from the outgoing stream

### SCENARIO-MSG-019: Queue full handling
**Given** a canister's input queue is full
**When** an incoming request arrives
**Then** the request is rejected with a queue full error

---

## REQ-MSG-005: Batch Time Monotonicity

The messaging system MUST enforce that batch times are strictly non-decreasing.

### SCENARIO-MSG-020: Non-increasing batch time
**Given** a batch arrives with a time not greater than the previous batch time
**When** the batch is processed
**Then** a critical error is logged (`mr_non_increasing_batch_time`)

---

## REQ-MSG-006: Registry-Based Configuration

The messaging system MUST read configuration from the IC registry for each batch.

### SCENARIO-MSG-021: Load subnet configuration from registry
**Given** a batch is processed
**When** registry configuration is loaded
**Then** subnet type, max canisters, execution settings, chain key settings, provisional whitelist, and canister allocation ranges are loaded

### SCENARIO-MSG-022: Registry read failure handling
**Given** the registry cannot be read
**When** the failure occurs
**Then** a critical error is logged (`mr_failed_to_read_registry_error`)

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-MSG-001 | Batch processing | narrative | rs/messaging/tests/messaging.rs |
| REQ-MSG-002 | State machine round | narrative | rs/messaging/tests/messaging.rs |
| REQ-MSG-003 | Stream builder | narrative | rs/messaging/tests/messaging.rs |
| REQ-MSG-004 | Stream handler | narrative | rs/messaging/tests/messaging.rs |
| REQ-MSG-005 | Batch time monotonicity | narrative | rs/messaging/tests/messaging.rs |
| REQ-MSG-006 | Registry configuration | narrative | rs/messaging/tests/messaging.rs |
