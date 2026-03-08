# Determinism Tests

The `ic-determinism-test` crate (`rs/determinism_test/`) verifies that the IC execution environment produces identical state hashes across multiple runs with the same inputs.

## Requirements

### Requirement: Execution Determinism Verification

The determinism test framework runs the same sequence of canister operations multiple times and asserts that the resulting state hashes are identical.

#### Scenario: Deterministic state hash across iterations
- **WHEN** `determinism_test(msgs)` is called with a list of message method names
- **THEN** a real `MessageRouting` and `StateManager` are set up using the internal `setup` module
- **AND** the test runs 10 iterations of the following:
  - Install canisters (2 per scheduler core) using WAT that performs memory writes
  - Execute the specified messages on all canisters
  - Request a full state hash
- **AND** all 10 state hashes are compared for equality
- **AND** the test passes only if all hashes are identical

#### Scenario: Test canister behavior
- **WHEN** the test WASM canister is installed
- **THEN** it exports two update methods: `dirty1` and `dirty2`
- **AND** `dirty1` writes value 99 to memory address 0 and replies
- **AND** `dirty2` writes value 99 to memory addresses 0 and 4096 and replies
- **AND** these methods exercise different page-dirtying patterns

#### Scenario: Canister installation determinism
- **WHEN** multiple canisters are installed per scheduler core
- **THEN** the installation uses `ProvisionalCreateCanisterWithCycles` and `InstallCode`
- **AND** each canister is installed with incrementing nonces for unique message IDs
- **AND** the order and content of canister creation is deterministic across runs

#### Scenario: Batch delivery
- **WHEN** `build_batch(message_routing, msgs)` constructs a batch
- **THEN** it uses `message_routing.expected_batch_height()` for the batch number
- **AND** uses fixed randomness `[0; 32]` and registry version 1
- **AND** time is set to `UNIX_EPOCH`

#### Scenario: Full state hash request
- **WHEN** `get_state_hash(message_routing, state_manager)` is called
- **THEN** a batch with `requires_full_state_hash = true` is delivered
- **AND** the function polls `state_manager.get_state_hash_at(latest_height)` until a hash is available
- **AND** transient errors (`HashNotComputedYet`, `StateNotFullyCertified`) are retried
- **AND** permanent errors cause a panic

#### Scenario: Ingress message completion
- **WHEN** `wait_for_ingress_message(reader, id)` is called
- **THEN** it polls the ingress history reader until the message reaches a terminal state
- **AND** `Completed(Reply(bytes))` returns the bytes
- **AND** `Completed(Reject(msg))` panics with the rejection message
- **AND** `Failed(error)` panics with the error details
