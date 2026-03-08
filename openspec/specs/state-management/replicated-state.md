# Replicated State

**Crates**: `ic-replicated-state`

The Replicated State represents the full deterministic state of a subnet, including all canister states, system metadata, message queues, and streams.

## Requirements

### Requirement: Replicated State Structure

The replicated state is composed of distinct sub-states that together represent the full state of a subnet.

#### Scenario: Top-level state composition
- **WHEN** a `ReplicatedState` is examined
- **THEN** it contains:
  - A map of `CanisterId` to `CanisterState` for all canisters on the subnet
  - `SystemMetadata` for subnet-level metadata
  - `SubnetQueues` (CanisterQueues) for subnet-level message routing
  - `StreamMap` for inter-subnet communication streams
  - `CanisterSnapshots` for all canister snapshots

### Requirement: Canister State Management

Each canister has a self-contained state encompassing execution, system, and scheduling data.

#### Scenario: Canister state composition
- **WHEN** a `CanisterState` is examined
- **THEN** it contains:
  - `SystemState` - cycles balance, controllers, status, queues, call contexts
  - `ExecutionState` (optional) - Wasm binary, heap memory, stable memory, globals
  - `SchedulerState` - scheduling metadata (priority, allocation, execution counters)

#### Scenario: Canister execution state
- **WHEN** a canister has an `ExecutionState`
- **THEN** it includes:
  - `WasmBinary` - the canister's Wasm module
  - `Memory` (wasm_memory) - heap memory as a `PageMap`
  - `Memory` (stable_memory) - stable memory as a `PageMap`
  - Exported globals
  - Exported functions
  - Wasm metadata (custom sections)

#### Scenario: Canister system state
- **WHEN** a canister's `SystemState` is examined
- **THEN** it includes:
  - `CanisterQueues` - input and output message queues
  - `CallContextManager` - tracking active call contexts and callbacks
  - Cycles balance and debit
  - Controllers set
  - `CanisterStatus` - Running, Stopping, or Stopped
  - `WasmChunkStore` - storage for Wasm module chunks
  - Canister history
  - Certified data
  - Task queue for pending execution tasks

### Requirement: Canister Status Lifecycle

Canisters follow a defined status lifecycle that affects message acceptance.

#### Scenario: Running canister accepts all messages
- **WHEN** a canister is in `Running` status
- **THEN** it accepts ingress messages, requests, and responses

#### Scenario: Stopping canister rejects new requests
- **WHEN** a canister is in `Stopping` status
- **THEN** it accepts only responses (not ingress messages or new requests)
- **AND** attempting to enqueue an ingress message returns `CanisterStopping` error

#### Scenario: Stopped canister rejects all messages
- **WHEN** a canister is in `Stopped` status
- **THEN** it rejects both ingress messages and requests
- **AND** it still accepts responses to outstanding calls

### Requirement: Message Queue Management

Canister queues manage input and output messages with round-robin scheduling.

#### Scenario: Input queue sources
- **WHEN** messages are consumed from input queues
- **THEN** they are drawn round-robin from three sources:
  - `LocalSubnet` - messages from canisters on the same subnet
  - `Ingress` - user ingress messages
  - `RemoteSubnet` - messages from other subnets

#### Scenario: Output queue iteration
- **WHEN** output messages are iterated
- **THEN** messages are consumed round-robin across canisters
- **AND** subnet queues are processed first (before canister queues)
- **AND** within each canister, output queues are iterated round-robin across destinations

#### Scenario: Queue full error
- **WHEN** a message is enqueued to a full input or output queue
- **THEN** a `QueueFull` error is returned with the queue capacity

#### Scenario: Guaranteed response memory limits
- **WHEN** a guaranteed response request would cause the subnet to exceed its memory limit
- **THEN** an `OutOfMemory` error is returned with the requested and available bytes

#### Scenario: Non-matching response rejection
- **WHEN** a response does not match any outstanding callback
- **THEN** a `NonMatchingResponse` error is returned

### Requirement: Stream Management

Streams provide reliable ordered messaging between subnets.

#### Scenario: Stream structure
- **WHEN** a `Stream` is examined
- **THEN** it contains:
  - A `StreamHeader` with begin/end indices and signal metadata
  - A `StreamIndexedQueue` of outgoing messages

#### Scenario: Stream message ordering
- **WHEN** messages are added to a stream
- **THEN** they receive monotonically increasing `StreamIndex` values
- **AND** messages are available in order from `messages_begin()` to `messages_end()`

### Requirement: System Metadata

System metadata tracks subnet-level state that is not canister-specific.

#### Scenario: System metadata contents
- **WHEN** `SystemMetadata` is examined
- **THEN** it includes:
  - Own subnet ID and subnet type
  - Network topology (routing table, subnet list)
  - Batch time
  - Previous state hash
  - Ingress history
  - Certification version
  - Subnet call context manager (for management canister calls)

### Requirement: Ingress History State

The ingress history tracks the status of all ingress messages.

#### Scenario: Ingress status lifecycle
- **WHEN** an ingress message is tracked
- **THEN** it transitions through statuses:
  - `Received` - message has been received
  - `Processing` - message is being executed
  - `Completed` - execution succeeded with a response
  - `Failed` - execution failed with an error
  - `Done` - final acknowledgment state
  - `Unknown` - message ID not found

### Requirement: Canister Snapshots

Canister snapshots provide point-in-time captures of canister state.

#### Scenario: Snapshot contents
- **WHEN** a `CanisterSnapshot` is examined
- **THEN** it contains:
  - A unique `SnapshotId`
  - The `CanisterId` it belongs to
  - Timestamp of capture
  - Canister version at time of capture
  - Wasm binary hash
  - Certified data
  - Execution state snapshot (Wasm memory, stable memory, globals)

#### Scenario: Snapshot storage
- **WHEN** snapshots are stored
- **THEN** each snapshot has its own directory under `snapshots/<canister_id>/<snapshot_id>/`
- **AND** memory is stored using the same PageMap overlay mechanism as canisters

### Requirement: State Invariants

The replicated state maintains both hard and soft invariants.

#### Scenario: Hard invariant violation on deserialization
- **WHEN** a hard invariant is violated during state deserialization
- **THEN** an error is returned and the state is not loaded

#### Scenario: Soft invariant violation on deserialization
- **WHEN** a soft invariant is violated during state deserialization
- **THEN** a critical error metric is incremented
- **AND** the state is still loaded (soft invariants are self-healing)

#### Scenario: Enum change compatibility
- **WHEN** an enum in the replicated state needs to be modified
- **THEN** changes must be rolled out in stages across multiple replica releases:
  - Adding a variant: first define it without use, then use it after deployment
  - Removing a variant: first remove all uses, then remove the definition after deployment
  - Remapping a variant: treat as concurrent removal and addition

### Requirement: State Splitting

The replicated state supports splitting for subnet migration.

#### Scenario: Splitting state for a new subnet
- **WHEN** `split(subnet_id, routing_table, batch_time)` is called
- **THEN** canisters not assigned to the subnet are removed
- **AND** streams are pruned to only include relevant subnets
- **AND** the subnet ID in metadata is updated
- **AND** batch time is optionally overridden for the new subnet
- **AND** a split marker is recorded in the state

### Requirement: Dropped Message Metrics

The state tracks metrics for messages that are timed out or shed.

#### Scenario: Message timeout tracking
- **WHEN** a message times out
- **THEN** the `observe_timed_out_message` metric is recorded
- **AND** it is categorized by kind (request/response), context (inbound/outbound), and class (guaranteed/best-effort)

#### Scenario: Message shedding tracking
- **WHEN** a message is shed (dropped due to load)
- **THEN** the `observe_shed_message` metric is recorded
- **AND** it is categorized by kind and context, including the byte size
