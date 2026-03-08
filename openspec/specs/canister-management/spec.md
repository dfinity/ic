# Rust Canisters Specification

**Crates**: `blob-store`, `canister_http`, `canister-creator`, `cloner-canister-types`, `http_counter`, `kv_store`, `ic-sender-canister`, `ic-universal-canister`, `universal-canister`

This specification covers the Rust canister libraries and test canisters under `rs/rust_canisters/`, which provide foundational utilities for building and testing IC canisters in Rust.

---

## Requirements

### Requirement: Canister Logging (canister_log)

The `ic_canister_log` crate provides a thread-local ring buffer for canister log messages with a configurable capacity.

#### Scenario: Declare and use a log buffer
- **WHEN** a developer declares a log buffer with `declare_log_buffer!(name = LOG, capacity = 100)`
- **THEN** a thread-local `LogBuffer` is created with capacity for 100 entries
- **AND** messages can be logged using `log!(LOG, "message {}", arg)`

#### Scenario: Log buffer capacity overflow
- **WHEN** more messages are logged than the buffer capacity
- **THEN** the oldest messages are evicted to make room for new ones (ring buffer behavior)

#### Scenario: Log entry metadata
- **WHEN** a message is logged
- **THEN** the log entry includes a timestamp, the message text, the source file path, and the source line number

#### Scenario: Global entry counter
- **WHEN** multiple log entries are created
- **THEN** each entry receives a monotonically increasing counter value via `entry_counter`

---

### Requirement: Candid Encoding/Decoding (dfn_candid)

The `dfn_candid` crate provides helper functions for encoding and decoding Candid-formatted inter-canister messages.

#### Scenario: Encode and decode Candid arguments
- **WHEN** a canister function receives Candid-encoded arguments
- **THEN** the `dfn_candid` helpers correctly deserialize the arguments
- **AND** can serialize response values back to Candid format

---

### Requirement: Protobuf Encoding/Decoding (dfn_protobuf)

The `dfn_protobuf` crate provides helper functions for encoding and decoding Protobuf-formatted inter-canister messages.

#### Scenario: Encode and decode Protobuf arguments
- **WHEN** a canister function receives Protobuf-encoded arguments
- **THEN** the `dfn_protobuf` helpers correctly deserialize the arguments
- **AND** can serialize response values back to Protobuf format

---

### Requirement: HTTP Metrics (dfn_http_metrics)

The `dfn_http_metrics` crate provides Prometheus-compatible HTTP metrics endpoints for canisters.

#### Scenario: Expose canister metrics via HTTP
- **WHEN** a canister uses `dfn_http_metrics`
- **THEN** it can serve Prometheus-formatted metrics over the canister's HTTP interface

---

### Requirement: Canister HTTP Interface (dfn_http)

The `dfn_http` crate provides types and utilities for handling HTTP requests and responses within canisters.

#### Scenario: Parse HTTP request
- **WHEN** an HTTP request is received by a canister
- **THEN** the request method, URL, headers, and body are accessible through the `dfn_http` types

---

### Requirement: Canister Serve (canister_serve)

The `canister_serve` crate provides utilities for serving canister endpoints.

#### Scenario: Serve canister update and query methods
- **WHEN** a canister uses `canister_serve`
- **THEN** it can define and serve update and query methods

---

### Requirement: Proxy Canister

The proxy canister (`rs/rust_canisters/proxy_canister/`) is a test canister that forwards HTTP requests to external services using the Canister HTTP Calls feature.

#### Scenario: Forward HTTP request to external service
- **WHEN** the proxy canister receives an ingress message containing an HTTP request specification
- **THEN** it decodes the request and forwards it to the targeted external service
- **AND** returns the response to the caller if the call was successful and agreed upon by consensus

#### Scenario: Stress test with concurrent requests
- **WHEN** the proxy canister receives a `RemoteHttpStressRequest`
- **THEN** it sends the specified number of concurrent HTTP requests

---

### Requirement: XNet Test Canister

The XNet test canister (`rs/rust_canisters/xnet_test/`) is used to test cross-subnet (XNet) messaging.

#### Scenario: Cross-subnet message delivery
- **WHEN** the XNet test canister sends messages to canisters on other subnets
- **THEN** the messages are correctly routed and delivered via XNet streams

---

### Requirement: Canister Creator

The canister creator (`rs/rust_canisters/canister_creator/`) is a test canister that creates other canisters programmatically.

#### Scenario: Create child canister
- **WHEN** the canister creator is called
- **THEN** it creates a new canister using the management canister API

---

### Requirement: Stable Memory Integrity

The stable memory integrity canister (`rs/rust_canisters/stable_memory_integrity/`) tests that stable memory persists correctly across canister upgrades.

#### Scenario: Stable memory persists across upgrades
- **WHEN** a canister writes data to stable memory and is upgraded
- **THEN** the data in stable memory is preserved and readable after the upgrade

---

### Requirement: Load Simulator

The load simulator canister (`rs/rust_canisters/load_simulator/`) generates controlled workloads for performance testing.

#### Scenario: Generate controlled load
- **WHEN** the load simulator is invoked
- **THEN** it generates the specified workload pattern for testing system performance

---

### Requirement: Exchange Rate Mock (xrc_mock)

The XRC mock canister (`rs/rust_canisters/xrc_mock/`) provides a mock exchange rate canister for testing.

#### Scenario: Return mock exchange rates
- **WHEN** the XRC mock canister is queried for exchange rates
- **THEN** it returns preconfigured mock exchange rate data

---

### Requirement: Test Utilities

The test canisters under `rs/rust_canisters/tests/` provide test scenarios for:

#### Scenario: Canister upgrade lifecycle
- **WHEN** a canister is installed, then upgraded
- **THEN** pre_upgrade and post_upgrade hooks execute correctly

#### Scenario: Inter-canister calls
- **WHEN** one canister calls another canister
- **THEN** the call is routed correctly and the response is returned

#### Scenario: Inter-canister error handling
- **WHEN** an inter-canister call fails
- **THEN** the error is propagated correctly to the caller

#### Scenario: Panic handling
- **WHEN** a canister panics during execution
- **THEN** the panic is caught and a reject response is returned

#### Scenario: Canister management operations
- **WHEN** canister management operations (create, install, start, stop, delete) are performed
- **THEN** each operation succeeds or returns an appropriate error

#### Scenario: Time operations
- **WHEN** a canister reads the current time
- **THEN** it receives the IC consensus time

#### Scenario: Stable memory operations
- **WHEN** a canister reads and writes stable memory
- **THEN** the data is correctly stored and retrieved

#### Scenario: JSON encoding
- **WHEN** a canister encodes/decodes JSON data
- **THEN** the serialization and deserialization are correct

#### Scenario: NaN canonicalization
- **WHEN** floating-point NaN values are used in canister computation
- **THEN** NaN values are canonicalized for deterministic execution

#### Scenario: Ingress message handling
- **WHEN** ingress messages are sent to a canister
- **THEN** they are processed correctly according to the canister's defined methods
