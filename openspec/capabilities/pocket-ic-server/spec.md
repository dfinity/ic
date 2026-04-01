# PocketIC Server Capability Specification

**Source narrative**: `openspec/specs/pocket-ic-server/spec.md`
**Crates**: `pocket-ic-server`, `pocket-ic`, `pocket-ic-test-canister`
**Key files**: `rs/pocket_ic_server/`

---

## REQ-PIC-001: PocketIC Instance Lifecycle

The PocketIC server MUST manage the lifecycle of IC emulation instances.

### SCENARIO-PIC-001: Create a new PocketIC instance
**Given** a client sends a request to create a new instance with a subnet configuration
**When** the creation runs
**Then** the server creates a new PocketIC instance with the specified subnets
**And** returns an instance ID for subsequent operations

### SCENARIO-PIC-002: Multiple concurrent instances
**Given** multiple instances are created
**When** they operate
**Then** each instance operates independently with its own state

---

## REQ-PIC-002: Instance Configuration

PocketIC MUST support configurable subnet topologies and initial state.

### SCENARIO-PIC-003: Configure subnet types
**Given** creating an instance with `ExtendedSubnetConfigSet`
**When** configuration is applied
**Then** the instance can include system subnets, application subnets, and NNS subnets

### SCENARIO-PIC-004: Configure initial time
**Given** an initial time is specified in the instance configuration
**When** the instance starts
**Then** the instance starts with the specified IC time

---

## REQ-PIC-003: Deterministic State Machine

PocketIC MUST operate as a deterministic state machine.

### SCENARIO-PIC-005: Tick advances state
**Given** a `tick` operation is performed on an instance
**When** the tick executes
**Then** one round of computation executes deterministically
**And** all pending messages are processed

### SCENARIO-PIC-006: State is deterministic
**Given** the same sequence of operations is performed on two instances with the same initial state
**When** both run to completion
**Then** both instances arrive at the same final state

---

## REQ-PIC-004: Canister Operations

PocketIC MUST support standard canister lifecycle and interaction operations.

### SCENARIO-PIC-007: Submit and await ingress message
**Given** a client submits an ingress message via `/submit_ingress_message`
**When** `await_ingress_message` is called
**Then** the server processes ticks until the message completes
**And** returns the result (reply or reject)

### SCENARIO-PIC-008: Query a canister
**Given** a client sends a query via the `/query` endpoint
**When** the query executes
**Then** the query runs without modifying state and the result is returned

### SCENARIO-PIC-009: Manage canister resources
**Given** a client calls `/get_cycles`, `/add_cycles`, `/get_stable_memory`, or `/set_stable_memory`
**When** the request executes
**Then** cycles are returned/added or stable memory is read/written for the target canister

---

## REQ-PIC-005: Time Management

PocketIC MUST provide deterministic time control for testing.

### SCENARIO-PIC-010: Get and set instance time
**Given** a client calls GET `/get_time` or POST `/set_time`
**When** the request executes
**Then** the current IC time is returned, or the instance time is updated to the specified value

---

## REQ-PIC-006: IC HTTP Interface Compatibility

PocketIC MUST provide IC-compatible HTTP interface endpoints (v2/v3).

### SCENARIO-PIC-011: v2/v3 API endpoints
**Given** a client sends requests to `/api/v2/canister/{id}/call`, `/query`, `/read_state`, or `/api/v3/canister/{id}/call`
**When** requests are handled
**Then** they are processed compatible with the IC specification
**And** request bodies exceeding 4 MB receive a `PayloadTooLarge` error

---

## REQ-PIC-007: Canister HTTP Outcalls Mocking

PocketIC MUST support mocking HTTP outcalls made by canisters.

### SCENARIO-PIC-012: Get pending and mock HTTP requests
**Given** a canister makes an HTTP outcall
**When** a client calls GET `/get_canister_http` then POST `/mock_canister_http`
**Then** the pending HTTP outcall request is returned, then resolved with the provided mock response

---

## REQ-PIC-008: Topology and Subnet Information

PocketIC MUST provide topology information about the emulated network.

### SCENARIO-PIC-013: Get topology
**Given** a client sends GET `/topology`
**When** the request executes
**Then** the subnet topology including subnet IDs, types, and canister ranges is returned

---

## REQ-PIC-009: Blob Store

PocketIC MUST provide a blob store for storing and retrieving binary data.

### SCENARIO-PIC-016: Store and fetch blob
**Given** a binary blob is stored via the blob store API
**When** storage completes
**Then** a `BlobId` is returned
**And** subsequent fetch with that `BlobId` returns the original binary data

---

## REQ-PIC-010: Canister Snapshots

PocketIC MUST support downloading and uploading canister snapshots.

### SCENARIO-PIC-017: Download canister snapshot
**Given** a client sends POST `/canister_snapshot_download` with a canister ID and snapshot ID
**When** the request is handled
**Then** the server returns the binary snapshot data

### SCENARIO-PIC-018: Upload canister snapshot
**Given** a client sends POST `/canister_snapshot_upload` with snapshot data
**When** the request is handled
**Then** the snapshot is applied to the target canister

---

## REQ-PIC-011: Public Key Retrieval

PocketIC MUST expose subnet threshold signing public keys.

### SCENARIO-PIC-019: Get subnet public key
**Given** a client sends POST `/pub_key` with a subnet ID
**When** the request is handled
**Then** the threshold signing public key for the subnet is returned

---

## REQ-PIC-012: Auto-Progress Mode

PocketIC MUST support automatic time and tick advancement.

### SCENARIO-PIC-020: Enable auto-progress
**Given** a client configures auto-progress with `AutoProgressConfig`
**When** auto-progress is active
**Then** the instance automatically advances time and executes ticks at the configured rate

---

## REQ-PIC-013: HTTP Gateway Integration

PocketIC MUST support an optional HTTP gateway for serving canister HTTP interfaces.

### SCENARIO-PIC-021: Configure and query HTTP gateway
**Given** a client provides `HttpGatewayConfig` during instance creation
**When** the gateway starts
**Then** the instance starts an HTTP gateway that translates HTTP requests to canister calls
**And** `HttpGatewayDetails` including the listening address are available

---

## REQ-PIC-014: Operation Model

PocketIC MUST use an operation-based model with retry semantics and timeouts.

### SCENARIO-PIC-022: Operation retry on busy
**Given** an operation is submitted while the instance is busy
**And** the operation's `retry_if_busy()` returns true
**When** the operation is received
**Then** the operation is retried automatically

### SCENARIO-PIC-023: Processing timeout header
**Given** a client specifies the `processing-timeout-ms` header
**When** the server processes the request
**Then** the server respects the specified timeout for long-running operations
**And** the default retry timeout is 300 seconds

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-PIC-001 | Instance lifecycle | linked | rs/pocket_ic_server/tests/test.rs |
| REQ-PIC-002 | Configuration | linked | rs/pocket_ic_server/tests/test.rs |
| REQ-PIC-003 | Deterministic state machine | linked | rs/pocket_ic_server/tests/test.rs |
| REQ-PIC-004 | Canister operations | linked | rs/pocket_ic_server/tests/test.rs |
| REQ-PIC-005 | Time management | linked | rs/pocket_ic_server/tests/test.rs |
| REQ-PIC-006 | IC HTTP interface | narrative | rs/pocket_ic_server/tests/ |
| REQ-PIC-007 | HTTP outcall mocking | narrative | rs/pocket_ic_server/tests/ |
| REQ-PIC-008 | Topology info | narrative | rs/pocket_ic_server/tests/ |
