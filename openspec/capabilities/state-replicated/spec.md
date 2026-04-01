# State: Replicated State Capability Specification

**Source narrative**: `openspec/specs/state-management/replicated-state.md`
**Crates**: `ic-replicated-state`
**Key files**: `rs/replicated_state/src/`

---

## REQ-STATE-001: Replicated State Structure

The replicated state MUST contain all sub-states composing the full subnet state.

### SCENARIO-STATE-001: Top-level state composition
**Given** a `ReplicatedState` is examined
**When** its contents are checked
**Then** it contains: a map of `CanisterId` → `CanisterState`, `SystemMetadata`, `SubnetQueues`, `StreamMap`, and `CanisterSnapshots`

---

## REQ-STATE-002: Canister State Management

Each canister MUST have a self-contained state encompassing execution, system, and scheduling data.

### SCENARIO-STATE-002: Canister state composition
**Given** a `CanisterState` is examined
**When** its contents are checked
**Then** it contains: `SystemState` (cycles, controllers, status, queues, call contexts), optional `ExecutionState` (Wasm, heap, stable memory, globals), and `SchedulerState` (priority, allocation, counters)

---

## REQ-STATE-003: Canister Status Lifecycle

Canisters MUST follow a defined status lifecycle affecting message acceptance.

### SCENARIO-STATE-003: Running canister accepts all messages
**Given** a canister is in `Running` status
**When** messages arrive
**Then** it accepts ingress messages, requests, and responses

### SCENARIO-STATE-004: Stopping canister rejects new requests
**Given** a canister is in `Stopping` status
**When** a new ingress or request arrives
**Then** it is rejected with `CanisterStopping`
**And** the canister still accepts responses to outstanding calls

### SCENARIO-STATE-005: Stopped canister rejects all messages
**Given** a canister is in `Stopped` status
**When** ingress or new requests arrive
**Then** they are rejected
**And** responses to outstanding calls are still accepted

---

## REQ-STATE-004: Message Queue Management

Canister queues MUST manage input and output messages with round-robin scheduling.

### SCENARIO-STATE-006: Round-robin input queue sources
**Given** messages are consumed from input queues
**When** the next message is fetched
**Then** they are drawn round-robin from `LocalSubnet`, `Ingress`, and `RemoteSubnet` sources

### SCENARIO-STATE-007: Queue full error
**Given** a message is enqueued to a full input or output queue
**When** enqueuing runs
**Then** a `QueueFull` error is returned with the queue capacity

### SCENARIO-STATE-008: Guaranteed response memory limit
**Given** a guaranteed response request would exceed subnet memory limits
**When** enqueuing runs
**Then** an `OutOfMemory` error is returned

---

## REQ-STATE-005: Stream Management

Streams MUST provide reliable ordered messaging between subnets.

### SCENARIO-STATE-009: Stream message ordering
**Given** messages are added to a stream
**When** they are assigned indices
**Then** messages receive monotonically increasing `StreamIndex` values
**And** messages are available in order from `messages_begin()` to `messages_end()`

---

## REQ-STATE-006: Ingress History State

The ingress history MUST track the status of all ingress messages.

### SCENARIO-STATE-010: Ingress status lifecycle
**Given** an ingress message is tracked
**When** it progresses
**Then** it transitions through: `Received` → `Processing` → `Completed` | `Failed` → `Done`
**And** `Unknown` is returned for message IDs not in history

---

## REQ-STATE-007: Canister Snapshots

Canister snapshots MUST capture point-in-time state.

### SCENARIO-STATE-011: Snapshot contents
**Given** a `CanisterSnapshot` is examined
**When** its contents are checked
**Then** it contains: unique `SnapshotId`, `CanisterId`, timestamp, canister version, Wasm binary hash, certified data, and execution state snapshot (Wasm memory, stable memory, globals)

---

## REQ-STATE-008: State Invariants

The replicated state MUST maintain hard and soft invariants.

### SCENARIO-STATE-012: Hard invariant violation on deserialization
**Given** a hard invariant is violated during state deserialization
**When** loading runs
**Then** an error is returned and the state is not loaded

### SCENARIO-STATE-013: Soft invariant violation on deserialization
**Given** a soft invariant is violated during state deserialization
**When** loading runs
**Then** a critical error metric is incremented
**And** the state is still loaded (soft invariants are self-healing)

---

## REQ-STATE-009: State Splitting

The replicated state MUST support splitting for subnet migration.

### SCENARIO-STATE-014: Splitting state for new subnet
**Given** `split(subnet_id, routing_table, batch_time)` is called
**When** splitting runs
**Then** canisters not assigned to the subnet are removed
**And** streams are pruned to relevant subnets
**And** the subnet ID in metadata is updated

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-STATE-001 | State structure | narrative | rs/replicated_state/tests/ |
| REQ-STATE-002 | Canister state | narrative | rs/replicated_state/tests/ |
| REQ-STATE-003 | Status lifecycle | narrative | rs/replicated_state/tests/ |
| REQ-STATE-004 | Queue management | narrative | rs/replicated_state/tests/ |
| REQ-STATE-005 | Stream management | narrative | rs/replicated_state/tests/ |
| REQ-STATE-006 | Ingress history | narrative | rs/replicated_state/tests/ |
| REQ-STATE-007 | Snapshots | narrative | rs/replicated_state/tests/ |
| REQ-STATE-008 | Invariants | narrative | rs/replicated_state/tests/ |
| REQ-STATE-009 | State splitting | narrative | rs/replicated_state/tests/ |
