# System Tests Framework

**Crates**: `consensus-backup-system-tests`, `consensus-orchestrator-system-tests`, `consensus-tecdsa-system-tests`, `consensus-upgrade-system-tests`, `consensus-vetkd-system-tests`, `execution-system-tests`, `financial_integrations-system-tests`, `guest_upgrade_tests`, `ic_boundary_node_system_tests`, `ic_consensus_system_test_catch_up_test_common`, `ic_consensus_system_test_liveness_test_common`, `ic_consensus_system_test_node_registration_test_common`, `ic_consensus_system_test_subnet_recovery`, `ic_consensus_system_test_utils`, `ic_consensus_system_tests`, `ic_consensus_threshold_sig_system_test_utils`, `ic_crypto_system_tests`, `ic-boundary-nodes-integration-test-common`, `ic-boundary-nodes-performance-test-common`, `ic-boundary-nodes-system-test-utils`, `ic-system-test-driver`, `message-routing-system-tests`, `message-routing-system-tests-xnet`, `networking-system-tests`, `nns-system-tests`, `node-system-tests`, `rosetta-system-tests`, `rust-canister-tests`, `sdk-system-tests`, `sns_system_test_lib`, `sns_tests`, `systest-message-routing-common`, `xnet-slo-test-lib`, `xnet-test`

The system tests framework (`rs/tests/`) provides end-to-end testing infrastructure for the Internet Computer, spinning up real IC nodes in virtual machines managed by the Farm service.

## Requirements

### Requirement: System Test Driver Architecture

The driver (`rs/tests/driver/`) orchestrates the lifecycle of system tests: resource allocation, IC deployment, test execution, and teardown.

#### Scenario: Test environment setup
- **WHEN** a system test begins
- **THEN** the driver creates a `TestEnv` backed by a file-system directory structure
- **AND** the test environment contains the registry local store, SSH keys, and configuration
- **AND** the environment is persisted for debugging if tests fail

#### Scenario: Farm resource management
- **WHEN** `Farm::new(base_url, logger)` is created
- **THEN** it provides HTTP-based resource management for VMs
- **AND** supports creating/deleting VMs, uploading images, and managing DNS records
- **AND** uses configurable timeouts with linear backoff for retries

#### Scenario: VM lifecycle management
- **WHEN** VMs are needed for a test
- **THEN** the `Farm` service allocates VMs with specified resources (CPU, memory, disk)
- **AND** VMs can be started, stopped, killed, and rebooted via `node.vm()` methods
- **AND** VM allocation strategies include: distribute to arbitrary host, within single host, or across DCs

### Requirement: Internet Computer Topology Declaration

The `InternetComputer` builder declares the topology of the IC under test.

#### Scenario: Declare IC with subnets
- **WHEN** `InternetComputer::new().add_subnet(subnet).build()` is called
- **THEN** the IC topology is declared with the specified subnets
- **AND** each subnet can have a configurable number of nodes, type, and features

#### Scenario: Configure subnet properties
- **WHEN** a `Subnet` is configured
- **THEN** it supports setting: subnet type, number of nodes, DKG interval, unit delay, initial notary delay
- **AND** chain key configuration, malicious behavior, and custom VM resources

#### Scenario: Add unassigned nodes
- **WHEN** `with_unassigned_nodes(count)` is called
- **THEN** the specified number of nodes are added without subnet assignment
- **AND** they can later be assigned to subnets via NNS proposals

#### Scenario: Fast subnet configuration
- **WHEN** `add_fast_single_node_subnet(subnet_type)` is called
- **THEN** a single-node subnet with reduced block time is created for faster test execution

### Requirement: Test Environment API

The `test_env_api` module provides an ergonomic API for interacting with the deployed IC.

#### Scenario: Take topology snapshot
- **WHEN** `env.topology_snapshot()` is called
- **THEN** a `TopologySnapshot` reflecting the IC topology at the latest local registry version is returned
- **AND** subnets and nodes can be iterated via `subnets()` and `nodes()` methods

#### Scenario: Select and interact with nodes
- **WHEN** a node is selected from the topology snapshot
- **THEN** `node.get_public_api_url()` returns the node's public API URL
- **AND** `node.build_default_agent()` creates an `agent-rs` agent for canister interaction
- **AND** `node.with_default_agent(|agent| async { ... })` provides a scoped agent

#### Scenario: Synchronous-by-default design
- **WHEN** the test env API is used
- **THEN** all operations are synchronous by default
- **AND** state is persisted to the filesystem for debugging
- **AND** registry updates require explicit sync operations from a chosen node

### Requirement: Test Organization

System tests are organized by subsystem under `rs/tests/`.

#### Scenario: Consensus tests
- **WHEN** tests under `rs/tests/consensus/` are run
- **THEN** they verify consensus protocol behavior including finalization, CUP, and payload building

#### Scenario: Execution tests
- **WHEN** tests under `rs/tests/execution/` are run
- **THEN** they verify canister execution behavior including cycles, memory, and inter-canister calls

#### Scenario: Networking tests
- **WHEN** tests under `rs/tests/networking/` are run
- **THEN** they verify P2P, transport, and HTTP endpoint behavior

#### Scenario: NNS tests
- **WHEN** tests under `rs/tests/nns/` are run
- **THEN** they verify Network Nervous System governance, proposal execution, and registry updates

#### Scenario: Boundary node tests
- **WHEN** tests under `rs/tests/boundary_nodes/` are run
- **THEN** they verify boundary node routing, caching, and certificate validation

#### Scenario: Cross-chain tests
- **WHEN** tests under `rs/tests/cross_chain/` or `rs/tests/ckbtc/` are run
- **THEN** they verify Bitcoin integration, ckBTC minting/burning, and chain-key operations

#### Scenario: Message routing tests
- **WHEN** tests under `rs/tests/message_routing/` are run
- **THEN** they verify XNet messaging, state sync, and canister migration

### Requirement: Test Canisters

Test canisters (`rs/tests/test_canisters/`) provide purpose-built WASM binaries for system tests.

#### Scenario: Counter canister
- **WHEN** the counter canister (defined in `counter.wat`) is used
- **THEN** it provides a simple stateful canister for basic ingress and query testing

### Requirement: Workload Engine

The `generic_workload_engine` module provides infrastructure for load testing.

#### Scenario: Generate workload
- **WHEN** the workload engine is configured with target nodes and request generators
- **THEN** it generates sustained load against the IC
- **AND** measures latency, throughput, and error rates
- **AND** supports configurable concurrency and duration

### Requirement: NNS Client Utilities

The `nns` module provides helpers for interacting with the NNS in system tests.

#### Scenario: Submit NNS proposals
- **WHEN** NNS proposal helpers are used
- **THEN** they simplify creating, submitting, and awaiting governance proposals
- **AND** support common operations like subnet creation, node assignment, and replica upgrades

### Requirement: ICT Tool

The `ict` directory provides tooling for managing system test infrastructure.

#### Scenario: Test infrastructure management
- **WHEN** ICT commands are executed
- **THEN** they manage test environments, VMs, and Farm resources
