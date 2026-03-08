# PocketIC Server Specification

**Crates**: `pocket-ic-server`

This specification covers the PocketIC Server (`rs/pocket_ic_server/`), a self-contained, lightweight platform for testing canister smart contracts by emulating the Internet Computer locally.

---

## Requirements

### Requirement: PocketIC Instance Lifecycle

The PocketIC server manages the lifecycle of IC emulation instances.

#### Scenario: Create a new PocketIC instance
- **WHEN** a client sends a request to create a new instance with a subnet configuration
- **THEN** the server creates a new PocketIC instance with the specified subnets
- **AND** returns an instance ID for subsequent operations

#### Scenario: Delete a PocketIC instance
- **WHEN** a client sends a delete request for an instance ID
- **THEN** the server destroys the instance and frees associated resources

#### Scenario: Multiple concurrent instances
- **WHEN** multiple instances are created
- **THEN** each instance operates independently with its own state

---

### Requirement: Instance Configuration

PocketIC supports configurable subnet topologies.

#### Scenario: Configure subnet types
- **WHEN** creating an instance with `ExtendedSubnetConfigSet`
- **THEN** the instance can include system subnets, application subnets, and NNS subnets

#### Scenario: Configure initial time
- **WHEN** an initial time is specified in the instance configuration
- **THEN** the instance starts with the specified IC time

#### Scenario: ICP features configuration
- **WHEN** ICP features are specified
- **THEN** the instance is configured with the requested feature flags

---

### Requirement: Deterministic State Machine

PocketIC operates as a deterministic state machine where operations produce predictable state transitions.

#### Scenario: Tick advances state
- **WHEN** a `tick` operation is performed on an instance
- **THEN** the instance executes one round of computation deterministically
- **AND** all pending messages are processed

#### Scenario: Multiple ticks with configuration
- **WHEN** a `tick` operation is performed with `RawTickConfigs`
- **THEN** the instance can execute multiple rounds or customized tick behavior

#### Scenario: State is deterministic
- **WHEN** the same sequence of operations is performed on two instances with the same initial state
- **THEN** both instances arrive at the same final state

---

### Requirement: Canister Operations

PocketIC supports standard canister lifecycle and interaction operations.

#### Scenario: Submit ingress message
- **WHEN** a client submits an ingress message via the `/submit_ingress_message` endpoint
- **THEN** the message is queued for processing in the target canister

#### Scenario: Await ingress message
- **WHEN** a client calls `/await_ingress_message` after submitting a message
- **THEN** the server processes ticks until the message is completed
- **AND** returns the result (reply or reject)

#### Scenario: Query a canister
- **WHEN** a client sends a query via the `/query` endpoint (JSON format)
- **THEN** the query is executed without modifying state
- **AND** the result is returned

#### Scenario: Get cycles balance
- **WHEN** a client sends a request to `/get_cycles` with a canister ID
- **THEN** the server returns the canister's current cycles balance

#### Scenario: Add cycles to canister
- **WHEN** a client sends a request to `/add_cycles` with a canister ID and amount
- **THEN** the specified cycles are added to the canister

#### Scenario: Get canister controllers
- **WHEN** a client sends a request to `/get_controllers` with a canister ID
- **THEN** the server returns the list of controllers for the canister

#### Scenario: Get stable memory
- **WHEN** a client sends a request to `/get_stable_memory` with a canister ID
- **THEN** the server returns the canister's stable memory contents

#### Scenario: Set stable memory
- **WHEN** a client sends a request to `/set_stable_memory` with a canister ID and data
- **THEN** the canister's stable memory is overwritten with the provided data

#### Scenario: Get subnet for canister
- **WHEN** a client sends a request to `/get_subnet` with a canister ID
- **THEN** the server returns the subnet ID hosting that canister

---

### Requirement: Time Management

PocketIC provides deterministic time control for testing.

#### Scenario: Get current time
- **WHEN** a client sends a GET request to `/get_time`
- **THEN** the server returns the current IC time of the instance

#### Scenario: Set time
- **WHEN** a client sends a POST request to `/set_time` with a new time
- **THEN** the instance's IC time is updated to the specified value

#### Scenario: Set certified time
- **WHEN** a client sends a POST request to `/set_certified_time`
- **THEN** the certified time is updated independently

---

### Requirement: Topology and Status

PocketIC provides topology information about the emulated network.

#### Scenario: Get topology
- **WHEN** a client sends a GET request to `/topology`
- **THEN** the server returns the subnet topology including subnet IDs, types, and canister ranges

#### Scenario: Ingress message status
- **WHEN** a client sends a POST request to `/ingress_status` with a message ID
- **THEN** the server returns the current status of the ingress message (pending, completed, etc.)

---

### Requirement: IC HTTP Interface Compatibility (API v2/v3)

PocketIC provides an IC-compatible HTTP interface for standard IC clients.

#### Scenario: Status endpoint
- **WHEN** a client sends a GET request to `/api/v2/status`
- **THEN** the server returns a CBOR-encoded status response compatible with the IC specification

#### Scenario: Call endpoint v2
- **WHEN** a client sends a POST request to `/api/v2/canister/{canister_id}/call`
- **AND** the request body is within the size limit (4 MB)
- **THEN** the server processes the call request and returns an appropriate response

#### Scenario: Query endpoint v2
- **WHEN** a client sends a POST request to `/api/v2/canister/{canister_id}/query`
- **THEN** the server processes the query and returns the result

#### Scenario: Canister read_state endpoint v2
- **WHEN** a client sends a POST request to `/api/v2/canister/{canister_id}/read_state`
- **THEN** the server returns the requested state tree paths

#### Scenario: Subnet read_state endpoint v2
- **WHEN** a client sends a POST request to `/api/v2/subnet/{subnet_id}/read_state`
- **THEN** the server returns the requested subnet state tree paths

#### Scenario: Call endpoint v3
- **WHEN** a client sends a POST request to `/api/v3/canister/{canister_id}/call`
- **THEN** the server processes the synchronous call and returns the result

#### Scenario: Request body too large
- **WHEN** a client sends a request with a body exceeding 4 MB
- **THEN** the server returns a `PayloadTooLarge` error

---

### Requirement: Canister HTTP Outcalls Mocking

PocketIC supports mocking HTTP outcalls made by canisters.

#### Scenario: Get pending canister HTTP requests
- **WHEN** a client sends a GET request to `/get_canister_http`
- **THEN** the server returns any pending HTTP outcall requests from canisters

#### Scenario: Mock canister HTTP response
- **WHEN** a client sends a POST request to `/mock_canister_http` with a mock response
- **THEN** the pending HTTP outcall is resolved with the provided mock response

---

### Requirement: Canister Snapshots

PocketIC supports downloading and uploading canister snapshots.

#### Scenario: Download canister snapshot
- **WHEN** a client sends a POST request to `/canister_snapshot_download` with a canister ID and snapshot ID
- **THEN** the server returns the binary snapshot data

#### Scenario: Upload canister snapshot
- **WHEN** a client sends a POST request to `/canister_snapshot_upload` with snapshot data
- **THEN** the snapshot is applied to the target canister

---

### Requirement: Public Key Retrieval

PocketIC supports retrieving subnet public keys for verification.

#### Scenario: Get subnet public key
- **WHEN** a client sends a POST request to `/pub_key` with a subnet ID
- **THEN** the server returns the threshold signing public key for the subnet

---

### Requirement: Auto-Progress Mode

PocketIC supports an auto-progress mode where time and ticks advance automatically.

#### Scenario: Enable auto-progress
- **WHEN** a client configures auto-progress with `AutoProgressConfig`
- **THEN** the instance automatically advances time and executes ticks at the configured rate

---

### Requirement: HTTP Gateway Integration

PocketIC supports an optional HTTP gateway for serving canister HTTP interfaces.

#### Scenario: Configure HTTP gateway
- **WHEN** a client provides `HttpGatewayConfig` during instance creation
- **THEN** the instance starts an HTTP gateway that translates HTTP requests to canister calls

#### Scenario: Get HTTP gateway details
- **WHEN** an HTTP gateway is configured
- **THEN** the server provides `HttpGatewayDetails` including the listening address

---

### Requirement: Blob Store

PocketIC provides a blob store for storing and retrieving binary data.

#### Scenario: Store blob
- **WHEN** a binary blob is stored
- **THEN** a `BlobId` is returned that can be used to retrieve it later

#### Scenario: Fetch blob
- **WHEN** a `BlobId` is used to fetch a blob
- **THEN** the original binary data is returned if it exists

---

### Requirement: Operation Model

PocketIC uses an operation-based model for state transitions.

#### Scenario: Operation identification
- **WHEN** an operation is created
- **THEN** it has a unique `OpId` that identifies it

#### Scenario: Operation retry on busy
- **WHEN** an operation is submitted while the instance is busy
- **AND** the operation's `retry_if_busy()` returns true
- **THEN** the operation is retried automatically

#### Scenario: Timeout header support
- **WHEN** a client specifies the `processing-timeout-ms` header
- **THEN** the server respects the specified timeout for long-running operations
- **AND** the default retry timeout is 300 seconds

---

### Requirement: Beta Features

PocketIC supports gating experimental features behind a beta flag.

#### Scenario: Beta feature access
- **WHEN** beta features are enabled
- **THEN** additional experimental API endpoints and capabilities become available

---

### Requirement: Bitcoin and Dogecoin Integration Testing

PocketIC supports integration testing for Bitcoin and Dogecoin features.

#### Scenario: Bitcoin integration test
- **WHEN** a test uses PocketIC with Bitcoin integration
- **THEN** the Bitcoin canister functionality can be tested locally

#### Scenario: Dogecoin integration test
- **WHEN** a test uses PocketIC with Dogecoin integration
- **THEN** the Dogecoin canister functionality can be tested locally

---

### Requirement: Subnet Blockmaker Configuration

PocketIC supports configuring which nodes are blockmakers for each subnet.

#### Scenario: Configure subnet blockmakers
- **WHEN** `SubnetBlockmakers` is provided with a subnet, blockmaker, and failed blockmakers
- **THEN** the PocketIC instance uses this configuration for block production simulation

#### Scenario: Convert from raw blockmaker config
- **WHEN** a `RawSubnetBlockmakers` is received from the API
- **THEN** it is correctly converted to internal `SubnetBlockmakers` with proper Principal-to-NodeId mapping
