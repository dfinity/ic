# Replica Tests

**Crates**: `embedders_bench`, `execution-environment-bench`, `ic-ledger-suite-state-machine-tests`, `ic-ledger-suite-state-machine-tests-constants`, `ic-nervous-system-integration-tests`, `ic-nns-integration-tests`, `ic-query-stats-tests`, `ic-sns-integration-tests`, `ic-tests-ckbtc`, `ic-tests-cross-chain`, `ic-testnet-mainnet-nns`, `icp-rosetta-integration-tests`, `idx-tests`, `ic-registry-fetch-large-record-test-canister`, `testnets`

The `ic-replica-tests` crate (`rs/replica_tests/`) provides integration testing against a real single-replica environment with function-call interfaces instead of HTTP.

## Requirements

### Requirement: Local Test Runtime

The `LocalTestRuntime` provides a single-replica environment using real IC stack components connected via in-process channels.

#### Scenario: Initialize test runtime
- **WHEN** `canister_test(|runtime| { ... })` is called
- **THEN** a full IC replica stack is constructed with a single node
- **AND** a tokio runtime is created
- **AND** the registry is initialized from ic-prep output
- **AND** the runtime blocks until height 1 is reached before handing control to the test

#### Scenario: Initialize with custom config
- **WHEN** `canister_test_with_config(config, |runtime| { ... })` is called
- **THEN** the replica is configured with the provided `Config`
- **AND** a custom `IcConfig` topology can be supplied via `canister_test_with_ic_config`

#### Scenario: Create canister
- **WHEN** `runtime.create_canister()` is called
- **THEN** a `ProvisionalCreateCanisterWithCycles` ingress message is submitted
- **AND** the canister ID is extracted from the reply and returned
- **AND** the canister is provisioned with `1 << 120` cycles by default

#### Scenario: Install canister from WAT
- **WHEN** `runtime.install_canister(canister_id, wat, payload)` is called
- **THEN** the WAT is compiled to WASM
- **AND** an `InstallCode` ingress message is submitted to the management canister
- **AND** the result of installation is returned

#### Scenario: Upgrade canister
- **WHEN** `runtime.upgrade_canister(canister_id, wat, payload)` is called
- **THEN** an `InstallCode` message with mode `Upgrade` is submitted
- **AND** the canister module is replaced

#### Scenario: Execute ingress message
- **WHEN** `runtime.ingress(canister_id, method_name, payload)` is called
- **THEN** a signed ingress message is constructed with auto-incrementing nonce
- **AND** the message is sent through the ingress channel
- **AND** the function polls ingress history until completion or timeout (default 300s)
- **AND** the result (`WasmResult` or `UserError`) is returned

#### Scenario: Execute query
- **WHEN** `runtime.query(canister_id, method_name, payload).await` is called
- **THEN** a `Query` is constructed with anonymous user source
- **AND** the query waits for the latest state to be certified
- **AND** the query handler processes the request against certified state

#### Scenario: Ingress with custom sender
- **WHEN** `runtime.ingress_with_sender(canister_id, method, payload, sender)` is called
- **THEN** the ingress message is signed by the specified sender identity

#### Scenario: Process ingress with timeout
- **WHEN** an ingress message is submitted via `process_ingress`
- **AND** the message does not complete within the `ingress_time_limit`
- **THEN** the function panics with a timeout message

### Requirement: Universal Canister Testing

The `UniversalCanister` wrapper simplifies testing with the universal canister.

#### Scenario: Simple canister test
- **WHEN** `simple_canister_test(|uc| { ... })` is called
- **THEN** a `LocalTestRuntime` is created
- **AND** a universal canister is installed
- **AND** the `UniversalCanister` wrapper is provided to the test closure

#### Scenario: Universal canister query and update
- **WHEN** `uc.query(payload)` or `uc.update(payload)` is called
- **THEN** the "query" or "update" method of the universal canister is invoked
- **AND** the payload is the universal canister instruction bytecode

### Requirement: StateMachine-based Universal Canister

The `UniversalCanisterWithStateMachine` provides universal canister testing using the `StateMachine` backend.

#### Scenario: Install universal canister on StateMachine
- **WHEN** `install_universal_canister(env, args)` is called
- **THEN** the universal canister WASM is installed on the given `StateMachine`
- **AND** a `UniversalCanisterWithStateMachine` wrapper is returned

#### Scenario: Query and update via StateMachine
- **WHEN** `uc.query(payload)` or `uc.update(payload)` is called on `UniversalCanisterWithStateMachine`
- **THEN** the respective method is called on the `StateMachine` directly
- **AND** no network or ingress channel is involved

### Requirement: Test Assertions

Utility functions for asserting on canister call results.

#### Scenario: Assert reject
- **WHEN** `assert_reject(result, reject_code)` is called
- **THEN** it asserts the result is `Ok(WasmResult::Reject(msg))`
- **AND** the first byte of the rejection message matches the expected reject code

#### Scenario: Assert reply
- **WHEN** `assert_reply(result, bytes)` is called
- **THEN** it asserts the result is `Ok(WasmResult::Reply(data))`
- **AND** the reply data matches the expected bytes
