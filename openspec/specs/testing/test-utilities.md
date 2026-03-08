# Test Utilities

**Crates**: `attestation_testing`, `canister-test`, `ic-bitcoin-canister-mock`, `ic-btc-adapter-test-utils`, `ic-canonical-state-tree-hash-test-utils`, `ic-certification-test-utils`, `ic-ckdoge-minter-test-utils`, `ic-cketh-test-utils`, `ic-consensus-mocks`, `ic-crypto-iccsa-test-utils`, `ic-crypto-internal-csp-test-utils`, `ic-crypto-internal-test-vectors`, `ic-crypto-test-utils`, `ic-crypto-test-utils-canister-sigs`, `ic-crypto-test-utils-canister-threshold-sigs`, `ic-crypto-test-utils-crypto-returning-ok`, `ic-crypto-test-utils-csp`, `ic-crypto-test-utils-keygen`, `ic-crypto-test-utils-keys`, `ic-crypto-test-utils-local-csp-vault`, `ic-crypto-test-utils-metrics`, `ic-crypto-test-utils-multi-sigs`, `ic-crypto-test-utils-ni-dkg`, `ic-crypto-test-utils-reproducible-rng`, `ic-crypto-test-utils-root-of-trust`, `ic-crypto-test-utils-tls`, `ic-crypto-test-utils-vetkd`, `ic-crypto-tls-interfaces-mocks`, `ic-crypto-tree-hash-test-utils`, `ic-http-endpoints-test-agent`, `ic-icp-test-ledger`, `ic-icrc1-test-utils`, `ic-icrc3-test-ledger`, `ic-interfaces-certified-stream-store-mocks`, `ic-interfaces-mocks`, `ic-interfaces-registry-mocks`, `ic-interfaces-state-manager-mocks`, `ic-ledger-canister-blocks-synchronizer-test-utils`, `ic-ledger-suite-orchestrator-test-utils`, `ic-ledger-test-utils`, `ic-nervous-system-common-test-canister`, `ic-nervous-system-common-test-keys`, `ic-nervous-system-common-test-utils`, `ic-nns-delegation-manager-test-utils`, `ic-nns-test-utils`, `ic-nns-test-utils-golden-nns-state`, `ic-nns-test-utils-macros`, `ic-nns-test-utils-prepare-golden-state`, `ic-p2p-test-utils`, `ic-rosetta-test-utils`, `ic-sns-test-utils`, `ic-sns-testing`, `ic-test-artifact-pool`, `ic-test-identity`, `ic-test-utilities-embedders`, `ic-test-utilities-io`, `ic-test-utilities-registry`, `ic-test-utilities-serialization`, `ic-test-utilities-tmpdir`, `ic-types-test-utils`, `ic-validator-http-request-test-utils`, `ic-validator-ingress-message-test-canister`, `messaging-test-utils`, `mock_treasury_manager`, `rejoin-test-lib`, `rosetta_test_lib`, `sev_guest_testing`, `test-canister`, `xrc-mock`

The `ic-test-utilities` crate (`rs/test_utilities/`) and its sub-crates provide mock implementations, builders, helpers, and test infrastructure used across the IC codebase.

## Requirements

### Requirement: Core Test Utilities (ic-test-utilities)

The root crate re-exports the universal canister and provides modules for common test helpers.

#### Scenario: Assert cycles balance equality with tolerance
- **WHEN** `assert_balance_equals(expected, actual, epsilon)` is called
- **THEN** the assertion passes if `|expected - actual| < epsilon`
- **AND** panics with a descriptive message if the difference exceeds epsilon

#### Scenario: Empty WASM module
- **WHEN** the `empty_wasm` module is used
- **THEN** a valid but minimal WASM module is provided for tests that need a canister with no functionality

#### Scenario: Port allocation
- **WHEN** `port_allocation` module is used
- **THEN** unique ports are allocated for test processes to avoid conflicts

#### Scenario: Stable memory reader
- **WHEN** `stable_memory_reader` is used
- **THEN** it provides utilities to read canister stable memory contents in tests

### Requirement: Metrics Test Utilities (ic-test-utilities-metrics)

Provides functions to fetch and assert on Prometheus metric values from a `MetricsRegistry`.

#### Scenario: Fetch histogram stats
- **WHEN** `fetch_histogram_stats(registry, name)` is called
- **THEN** it returns `Option<HistogramStats>` with `count` and `sum` fields
- **AND** panics if the metric is a `HistogramVec` rather than a plain `Histogram`

#### Scenario: Fetch histogram vector stats
- **WHEN** `fetch_histogram_vec_stats(registry, name)` is called
- **THEN** it returns a `MetricVec<HistogramStats>` mapping label combinations to stats

#### Scenario: Fetch integer counter
- **WHEN** `fetch_int_counter(registry, name)` is called
- **THEN** it returns `Option<u64>` with the counter value

#### Scenario: Fetch integer counter vector
- **WHEN** `fetch_int_counter_vec(registry, name)` is called
- **THEN** it returns a `MetricVec<u64>` mapping label combinations to counter values

#### Scenario: Fetch integer gauge
- **WHEN** `fetch_int_gauge(registry, name)` is called
- **THEN** it returns `Option<u64>` with the gauge value

#### Scenario: Fetch gauge vector
- **WHEN** `fetch_gauge_vec(registry, name)` is called
- **THEN** it returns a `MetricVec<f64>` mapping label combinations to gauge values

#### Scenario: Construct label maps for assertions
- **WHEN** `labels(&[("key", "value")])` is called
- **THEN** a `BTreeMap<String, String>` is returned for use in metric assertions
- **AND** `metric_vec` constructs a `MetricVec` from label-value tuples for comparison

#### Scenario: Filter nonzero metrics
- **WHEN** `nonzero_values(metric_vec)` is called
- **THEN** only entries with non-zero values are retained

### Requirement: Time Test Utilities (ic-test-utilities-time)

Provides `FastForwardTimeSource` for deterministic time control in tests.

#### Scenario: Create new time source
- **WHEN** `FastForwardTimeSource::new()` is called
- **THEN** it returns an `Arc<FastForwardTimeSource>` starting at `UNIX_EPOCH`
- **AND** the monotonic instant is captured at creation time

#### Scenario: Set time forward
- **WHEN** `set_time(time)` is called with a time >= current time
- **THEN** both relative time and monotonic instant advance proportionally
- **AND** no desync is introduced between real and monotonic clocks

#### Scenario: Set time backward fails
- **WHEN** `set_time(time)` is called with a time < current time
- **THEN** `Err(TimeNotMonotoneError)` is returned
- **AND** the time source is unchanged

#### Scenario: Advance only monotonic time
- **WHEN** `advance_only_monotonic(duration)` is called
- **THEN** only the monotonic clock advances
- **AND** the relative (real) time remains unchanged
- **AND** `sync_realtime()` can later bring the real-time clock back in sync

#### Scenario: Advance both clocks
- **WHEN** `advance_time(duration)` is called
- **THEN** both the relative time and monotonic instant advance by the duration

#### Scenario: Timeout helper
- **WHEN** `with_timeout(duration, action)` is called
- **THEN** the action runs on a separate thread
- **AND** returns `true` if it completes within the duration, `false` otherwise

### Requirement: State Test Utilities (ic-test-utilities-state)

Provides builders for constructing `ReplicatedState` and `CanisterState` for tests.

#### Scenario: Build replicated state
- **WHEN** `ReplicatedStateBuilder::new().with_canister(canister).build()` is called
- **THEN** a `ReplicatedState` is constructed with the specified canisters
- **AND** subnet topology, routing table, and metadata are properly initialized

#### Scenario: Build canister state
- **WHEN** `CanisterStateBuilder::new().with_cycles(cycles).with_wasm(wasm).build()` is called
- **THEN** a `CanisterState` is constructed with the specified properties
- **AND** includes execution state, system state, and scheduler state

#### Scenario: Empty WASM binary
- **WHEN** `empty_wasm()` is called
- **THEN** an `Arc<WasmBinary>` containing a valid minimal WASM module is returned

#### Scenario: Mock ingress history
- **WHEN** `MockIngressHistory` is used
- **THEN** it implements `IngressHistoryReader` for testing ingress status lookup

### Requirement: Types Test Utilities (ic-test-utilities-types)

Provides test IDs, message builders, and arbitrary implementations.

#### Scenario: Test ID generators
- **WHEN** `canister_test_id(n)`, `subnet_test_id(n)`, `node_test_id(n)`, or `user_test_id(n)` is called
- **THEN** a deterministic test ID of the appropriate type is returned based on the input integer

#### Scenario: Signed ingress builder
- **WHEN** `SignedIngressBuilder::new().canister_id(id).method_name(name).build()` is called
- **THEN** a `SignedIngress` message is constructed with the specified parameters
- **AND** appropriate defaults are used for expiry, nonce, and sender

#### Scenario: Request builder
- **WHEN** `RequestBuilder::new().build()` is called
- **THEN** an inter-canister `Request` is constructed with test defaults

### Requirement: Consensus Test Utilities (ic-test-utilities-consensus)

Provides fake consensus pool cache and validation helpers.

#### Scenario: Fake consensus pool cache
- **WHEN** `FakeConsensusPoolCache::new(cup_proto)` is created
- **THEN** it implements `ConsensusPoolCache` with configurable finalized and summary blocks
- **AND** `update_cup(cup_proto)` allows updating the cached CUP during tests

#### Scenario: Changeset assertion macros
- **WHEN** `assert_changeset_matches_pattern!` is used
- **THEN** it asserts that a changeset has exactly one element matching the given pattern

#### Scenario: Validation result assertions
- **WHEN** `assert_result_invalid(result)` is called
- **THEN** it asserts the result is `Err(ValidationError::InvalidArtifact(_))`

### Requirement: Execution Environment Test Utilities (ic-test-utilities-execution-environment)

Provides test harnesses for the execution environment, hypervisor, and query handler.

#### Scenario: Execution test environment
- **WHEN** `ExecutionTest` is constructed
- **THEN** it provides a complete execution environment with state management
- **AND** supports canister installation, ingress execution, and query handling
- **AND** uses real execution components with configurable settings

#### Scenario: WAT canister builder
- **WHEN** `WatCanisterBuilder` is used
- **THEN** it allows programmatic construction of WAT (WebAssembly Text) canisters
- **AND** supports defining exported functions with custom code

### Requirement: Identity Test Utilities (ic-test-utilities-identity)

Provides test cryptographic identities.

#### Scenario: Test identity keypair
- **WHEN** `TEST_IDENTITY_KEYPAIR` is accessed
- **THEN** a deterministic Ed25519 keypair is returned (seeded with 1)
- **AND** it can be used for signing ingress messages in tests

#### Scenario: Get public key from private key
- **WHEN** `get_pub(private_key)` is called
- **THEN** the corresponding Ed25519 public key is returned
- **AND** if `None` is passed, a default hardcoded key is used

### Requirement: Load WASM Utility (ic-test-utilities-load-wasm)

Provides a utility for loading canister WASM binaries in tests.

#### Scenario: Load from environment variable on CI
- **WHEN** `load_wasm(manifest_dir, binary_name, features)` is called on CI
- **AND** the environment variable `<BINARY_NAME>_WASM_PATH` is set
- **THEN** the WASM binary is loaded from the path specified by the env var

#### Scenario: Build from source locally
- **WHEN** `load_wasm(manifest_dir, binary_name, features)` is called locally
- **AND** no environment variable is set
- **THEN** the WASM is built from source using `cargo build` targeting `wasm32-unknown-unknown`
- **AND** the `canister-release` profile is used

#### Scenario: Panic on CI without env var
- **WHEN** `load_wasm` is called on CI without the expected env var
- **THEN** it panics with a message instructing the developer to add the data dependency

### Requirement: Compare Dirs Utility (ic-test-utilities-compare-dirs)

Provides directory comparison for state persistence tests.

#### Scenario: Compare two directories
- **WHEN** two directory paths are compared
- **THEN** the utility recursively checks that all files match in content and structure

### Requirement: Logger Test Utilities (ic-test-utilities-logger)

Provides test logging infrastructure.

#### Scenario: With test replica logger
- **WHEN** `with_test_replica_logger(|logger| { ... })` is called
- **THEN** a `ReplicaLogger` suitable for test output is provided to the closure

### Requirement: In-Memory Logger (ic-test-utilities-in-memory-logger)

Provides an in-memory logger for capturing and asserting on log output.

#### Scenario: Capture log messages
- **WHEN** the in-memory logger is used in tests
- **THEN** log messages are stored in memory
- **AND** tests can assert on the content of logged messages
