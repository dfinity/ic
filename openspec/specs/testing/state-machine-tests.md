# State Machine Tests Framework

The `ic-state-machine-tests` crate (`rs/state_machine_tests/`) provides a lightweight, in-process replica environment for testing IC canister and subnet behavior without network overhead. It is the primary unit/integration testing tool for the IC stack.

## Requirements

### Requirement: StateMachine Construction and Configuration

The `StateMachine` provides a replicated state machine detached from the network layer. It wraps real replica components (execution environment, state manager, message routing, ingress manager) in a single-process test harness. A builder pattern (`StateMachineBuilder`) allows extensive configuration.

#### Scenario: Default construction
- **WHEN** a `StateMachine` is created via `StateMachine::new()` or `StateMachineBuilder::new().build()`
- **THEN** it initializes with a System subnet type
- **AND** uses a temporary directory for state storage
- **AND** creates a subnet with `SMALL_APP_SUBNET_MAX_SIZE` nodes
- **AND** starts at genesis time
- **AND** enables ECDSA, Schnorr signing, and VetKD by default
- **AND** enables HTTP outcalls feature
- **AND** sets checkpoint interval to 199 (System) or 499 (Application)
- **AND** uses a default seed of `[42; 32]`
- **AND** automatically increments time by 1 nanosecond per round

#### Scenario: Builder configuration for subnet type
- **WHEN** `StateMachineBuilder::new().with_subnet_type(SubnetType::Application).build()` is called
- **THEN** the `StateMachine` is configured as an Application subnet
- **AND** the checkpoint interval defaults to 499

#### Scenario: Builder configuration for chain keys
- **WHEN** `with_chain_key(key_id)` is called on the builder
- **THEN** the specified chain key is enabled on the subnet
- **AND** the key is registered in the routing table and subnet list

#### Scenario: Builder with persistent state directory
- **WHEN** `with_state_machine_state_dir(Box::new(path_buf))` is called
- **THEN** the state is persisted at the given path after the `StateMachine` is dropped
- **AND** the state can be reused by a new `StateMachine` constructed with the same path

#### Scenario: Builder with custom time
- **WHEN** `with_time(time)` or `with_current_time()` is called on the builder
- **THEN** the `StateMachine` initializes at the specified time
- **AND** subsequent rounds advance from that time

#### Scenario: Multi-subnet configuration
- **WHEN** `build_with_subnets(subnets)` is called on the builder
- **THEN** the `StateMachine` is registered in a shared pool of `StateMachine`s
- **AND** XNet payload building and certified stream slicing is enabled between subnets
- **AND** a `PayloadBuilderImpl` is instantiated for the subnet

### Requirement: Round Execution

The `StateMachine` provides methods to advance the IC state by executing rounds (batches).

#### Scenario: Basic round execution
- **WHEN** `execute_round()` is called
- **THEN** the latest state is certified
- **AND** a payload is assembled from the ingress pool, XNet, and canister HTTP pools
- **AND** message routing processes the batch
- **AND** time advances by the configured increment if not explicitly set

#### Scenario: Tick (simplified round)
- **WHEN** `tick()` is called
- **THEN** a single empty round is executed
- **AND** the state machine advances by one height

#### Scenario: Checkpointed tick
- **WHEN** `checkpointed_tick()` is called
- **THEN** a round is executed with `requires_full_state_hash` set to `true`
- **AND** a state checkpoint is created

#### Scenario: Execute with payload builder
- **WHEN** `do_execute_round(blockmaker_metrics)` is called
- **THEN** the ingress manager selects messages from the ingress pool
- **AND** XNet streams are refilled from peer subnets
- **AND** canister HTTP responses are inducted
- **AND** query stats payloads are processed
- **AND** threshold signing requests are fulfilled
- **AND** setup_initial_dkg responses are generated for NNS

### Requirement: Canister Lifecycle Management

The `StateMachine` provides methods to install, upgrade, and manage canisters.

#### Scenario: Install a canister with WASM bytes
- **WHEN** `install_canister(wasm, args, controller)` is called
- **THEN** a new canister is created with an auto-generated canister ID
- **AND** the WASM module is installed
- **AND** the `canister_init` method is called with the provided args
- **AND** the canister ID is returned

#### Scenario: Upgrade a canister
- **WHEN** `upgrade_canister(canister_id, wasm)` is called
- **THEN** the canister's WASM module is replaced
- **AND** `canister_pre_upgrade` is called on the old module
- **AND** `canister_post_upgrade` is called on the new module

#### Scenario: Execute ingress message
- **WHEN** `execute_ingress(canister_id, method, payload)` is called
- **THEN** a signed ingress message is constructed with the given parameters
- **AND** it is submitted and the state machine ticks until the message completes
- **AND** the result (Reply or Reject) is returned

#### Scenario: Submit ingress without executing
- **WHEN** `submit_ingress(canister_id, method, payload)` is called
- **THEN** the ingress message is placed in the ingress pool
- **AND** no round is executed
- **AND** the message ID is returned for later status checking

#### Scenario: Query call
- **WHEN** `query(canister_id, method, payload)` is called
- **THEN** the query is executed against the latest certified state
- **AND** the result is returned synchronously without advancing the state

### Requirement: State Inspection and Certification

The framework provides methods to inspect internal state and verify certifications.

#### Scenario: Read certified state
- **WHEN** `read_state_bitcoin_aux_info()` or other state reading methods are called
- **THEN** the certified state tree is read
- **AND** the appropriate data is extracted and returned

#### Scenario: Await state hash
- **WHEN** `await_state_hash()` is called
- **THEN** the function blocks until the state hash for the latest height is computed
- **AND** the `CryptoHashOfState` is returned

#### Scenario: Get ingress status
- **WHEN** `ingress_status(message_id)` is called
- **THEN** the current status of the ingress message is returned
- **AND** it may be `Unknown`, `Received`, `Processing`, `Completed`, `Failed`, or `Done`

### Requirement: Registry Management

The `StateMachine` manages a fake registry for test configuration.

#### Scenario: Add global registry records
- **WHEN** `add_global_registry_records()` is called
- **THEN** root subnet ID, routing table, subnet list, chain key, and node rewards records are added

#### Scenario: Add initial registry records
- **WHEN** `add_initial_registry_records()` is called
- **THEN** provisional whitelist, blessed replica versions, and replica version records are added

#### Scenario: Reload registry
- **WHEN** `reload_registry()` is called after modifying the shared registry data provider
- **THEN** the registry client updates to the latest version
- **AND** the CUP in the consensus pool cache is refreshed

### Requirement: Threshold Signing Simulation

The `StateMachine` simulates threshold signing for ECDSA, Schnorr, and VetKD.

#### Scenario: ECDSA signing
- **WHEN** a canister requests an ECDSA signature via the management canister
- **AND** ECDSA signing is enabled on the subnet
- **THEN** the `StateMachine` deterministically produces a valid ECDSA signature
- **AND** the signature can be verified against the subnet's public key

#### Scenario: Schnorr signing
- **WHEN** a canister requests a Schnorr signature
- **THEN** the `StateMachine` produces a valid Ed25519 or BIP-340 signature depending on the algorithm

### Requirement: Mock Components

The `StateMachine` uses mock implementations for components not needed in tests.

#### Scenario: Fake verifier
- **WHEN** certification verification is requested
- **THEN** `FakeVerifier` always returns `Ok(())`, bypassing cryptographic verification

#### Scenario: Pocket ingress pool
- **WHEN** ingress messages are submitted
- **THEN** they are stored in `PocketIngressPool` which implements `IngressPool`
- **AND** messages are indexed by expiry time and message ID

#### Scenario: Pocket consensus time
- **WHEN** the `StateMachine` time changes
- **THEN** `PocketConsensusTime` is updated to reflect the new time
- **AND** the ingress manager uses this time for message selection

#### Scenario: XNet mocking
- **WHEN** multiple `StateMachine`s are connected via `build_with_subnets`
- **THEN** `PocketXNetImpl` fetches certified stream slices from peer state machines
- **AND** slices are pooled in a `CertifiedSlicePool` for XNet payload building
