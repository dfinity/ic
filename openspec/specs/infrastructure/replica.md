# Replica

**Crates**: `ic-replica-setup-ic-network`, `load-simulator`

The replica is the core process of an Internet Computer node. It runs the IC protocol stack including consensus, execution, state management, networking, and the HTTP handler. The replica is managed by the orchestrator and communicates with peers via the P2P layer.

## Requirements

### Requirement: Replica Startup and Initialization
The replica must parse its configuration, set up crypto components, determine its subnet membership, and construct the full IC stack before serving requests.

#### Scenario: Argument parsing
- **WHEN** the replica binary starts
- **THEN** command-line arguments are parsed via `clap` into `ReplicaArgs`
- **AND** the `--print-sample-config` flag causes the sample config to be printed and the process to exit
- **AND** the replica version from the arguments is set as the default via `ReplicaVersion::set_default_version`

#### Scenario: Configuration source resolution
- **WHEN** the replica determines its configuration source
- **THEN** it checks for `--config LITERAL`, a file argument, stdin (`-`), or the default `./ic.json5`
- **AND** if no valid source is found, usage information is printed and the process exits

#### Scenario: Catch-up package loading
- **WHEN** the replica starts with a CUP file path argument
- **THEN** the CUP is read from the specified protobuf file
- **AND** failure to load the CUP causes a panic (the orchestrator should have ensured its availability)
- **WHEN** no CUP file is provided (e.g., in local development with dfx)
- **THEN** a registry CUP is generated from the registry

### Requirement: Process Group Setup
The replica establishes itself as a process group leader to enable the orchestrator to manage all its child processes.

#### Scenario: Process group creation
- **WHEN** the replica main function starts
- **THEN** it calls `setpgid(0, 0)` to create a new process group
- **AND** this ensures that `SIGTERM` sent to the group terminates all child processes (e.g., canister_sandbox)
- **AND** SELinux policy restricts child processes from calling `setpgid` to maintain group integrity

### Requirement: Runtime Architecture
The replica uses multiple Tokio runtimes as a risk mitigation measure to prevent bugs in one component from blocking others.

#### Scenario: Multiple Tokio runtimes
- **WHEN** the replica initializes its async runtime environment
- **THEN** four separate Tokio runtimes are created: rt_main (crypto, IPC), rt_p2p (peer-to-peer), rt_http (HTTP handler), and rt_xnet (cross-subnet messaging)
- **AND** each runtime uses `max(num_cpus / 4, 2)` worker threads
- **AND** this isolation prevents a blocking bug in one component from stalling others

### Requirement: Binary Hash Verification
The replica computes and records its own binary hash for attestation and version verification.

#### Scenario: Replica binary hash computation
- **WHEN** the replica starts
- **THEN** it computes the SHA-256 hash of its own binary file
- **AND** the hash is stored in the `REPLICA_BINARY_HASH` global for later use
- **AND** the binary path and hash are logged at startup

### Requirement: Crypto and Registry Setup
The replica initializes cryptographic components and connects to the registry for configuration data.

#### Scenario: Crypto provider setup
- **WHEN** `setup_crypto_registry` is called
- **THEN** a `LocalStoreImpl` is created from the configured local store path
- **AND** a `RegistryClientImpl` is initialized with the local store as data provider
- **AND** `fetch_and_start_polling` is called on the registry client (panics on failure)
- **AND** a `CryptoComponent` is created with the registry, ensuring the crypto root directory has required permissions

### Requirement: Subnet Discovery
The replica must determine which subnet it belongs to by consulting the registry.

#### Scenario: Subnet ID lookup
- **WHEN** the replica looks up its subnet ID
- **THEN** it uses the CUP's registry version (if available) or the latest registry version
- **AND** it iterates through all subnets to find the one containing this node's ID
- **AND** if the node is not found in any subnet after 10 retries, the replica panics

#### Scenario: Subnet type determination
- **WHEN** the replica determines the subnet type (System, Application, VerifiedApplication)
- **THEN** the subnet record is fetched from the registry
- **AND** failure to parse the subnet type causes a fatal error
- **AND** the subnet type influences execution limits, scheduling, and resource allocation

### Requirement: IC Stack Construction
The replica wires together all major components into a functioning IC node.

#### Scenario: Consensus pool initialization
- **WHEN** `construct_ic_stack` is called
- **THEN** the consensus pool directory is created if it does not exist
- **AND** replica version compatibility of the persistent pool is verified
- **AND** a `ConsensusPoolImpl` is created with the CUP proto

#### Scenario: CUP selection from orchestrator
- **WHEN** the replica receives a CUP from the orchestrator via command-line
- **THEN** it deserializes the CUP proto (panicking on failure)
- **AND** it distinguishes between signed CUPs (from subnet consensus) and unsigned CUPs (from registry for genesis/recovery)

#### Scenario: Execution services initialization
- **WHEN** the IC stack is constructed
- **THEN** `ExecutionServices` are created with the subnet configuration based on the subnet type
- **AND** a `StateManagerImpl` is initialized for state persistence
- **AND** a `MessageRoutingImpl` is created for inter-canister message delivery

#### Scenario: Component wiring
- **WHEN** all components are initialized
- **THEN** consensus and P2P are set up via `setup_consensus_and_p2p`
- **AND** the XNet endpoint is started for cross-subnet communication
- **AND** Bitcoin adapter clients and HTTPS outcalls adapter are configured
- **AND** the NNS delegation manager is started if applicable

### Requirement: Subnet Configuration
Different subnet types have different execution parameters and resource limits.

#### Scenario: Application subnet configuration
- **WHEN** the subnet type is `Application`
- **THEN** default instruction limits apply (40B per message, 2B per slice, 4B per round)
- **AND** deterministic time slicing is configured with 2B instructions per slice

#### Scenario: System subnet configuration
- **WHEN** the subnet type is `System`
- **THEN** instruction limits are multiplied by SYSTEM_SUBNET_FACTOR (10x)
- **AND** this allows system canisters (NNS governance, registry, etc.) to perform heavier computations

### Requirement: Metrics and Profiling
The replica exposes metrics and supports CPU profiling for diagnostics.

#### Scenario: Metrics endpoint
- **WHEN** the replica is running
- **THEN** a `MetricsHttpEndpoint` serves Prometheus metrics
- **AND** the global `MetricsRegistry` collects metrics from all components

#### Scenario: Jemalloc metrics on Linux
- **WHEN** the replica runs on Linux
- **THEN** jemalloc is used as the global allocator
- **AND** jemalloc memory statistics are exposed as metrics

#### Scenario: CPU profiling
- **WHEN** the profiler feature is enabled
- **THEN** a pprof profiler guard is started at 100 Hz sampling frequency
- **AND** CPU profiles can be collected for performance analysis
