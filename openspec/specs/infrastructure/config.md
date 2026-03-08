# Configuration

**Crates**: `icp-config`, `config_types_compatibility_lib`

The IC configuration system defines the runtime parameters for all replica components. It supports loading from files, stdin, or string literals, with per-component sections that can be independently defaulted. The configuration covers transport, state management, execution, HTTP handling, metrics, consensus pools, cryptography, logging, and more.

## Requirements

### Requirement: Replica Configuration Structure
The replica uses a comprehensive configuration structure that covers all subsystem parameters.

#### Scenario: Full config structure
- **WHEN** a Config is constructed
- **THEN** it contains the following component configurations:
  - `registry_client` - Registry client connection settings
  - `transport` - Network transport configuration
  - `state_manager` - State persistence paths and settings
  - `hypervisor` - Execution environment (Wasm runtime) settings
  - `http_handler` - HTTP endpoint configuration
  - `metrics` - Metrics collection and export settings
  - `artifact_pool` - Consensus pool paths and settings
  - `crypto` - Cryptographic component configuration
  - `logger` - Logging configuration
  - `tracing` - Distributed tracing configuration
  - `orchestrator_logger` - Separate logger for the orchestrator
  - `csp_vault_logger` - Separate logger for the CSP vault
  - `message_routing` - Inter-canister messaging settings
  - `malicious_behavior` - Test-only malicious behavior flags
  - `firewall` - Replica firewall configuration
  - `boundary_node_firewall` - Boundary node firewall configuration
  - `registration` - Node registration settings
  - `nns_registry_replicator` - NNS registry replicator settings
  - `adapters_config` - External adapter (Bitcoin, HTTPS outcalls) settings
  - `bitcoin_payload_builder_config` - Bitcoin integration settings
  - `initial_ipv4_config` - Initial IPv4 network configuration
  - `domain` - Node domain name

### Requirement: Configuration Loading
Configuration can be loaded from multiple sources with optional sections using defaults.

#### Scenario: Loading from file
- **WHEN** a configuration file path is provided
- **THEN** the file is parsed as JSON5 format
- **AND** any omitted sections use values from the default Config

#### Scenario: Loading from stdin
- **WHEN** the config source is stdin (`-`)
- **THEN** the configuration is read from standard input and parsed

#### Scenario: Loading from literal
- **WHEN** the `--config` flag is used with a literal string
- **THEN** the string is parsed directly as configuration

#### Scenario: Default configuration
- **WHEN** no configuration source is specified and no `./ic.json5` file exists
- **THEN** the default configuration is used
- **AND** all paths are relative to the configured parent directory

#### Scenario: Optional section defaults
- **WHEN** a configuration file omits a section (via `ConfigOptional`)
- **THEN** the omitted section takes its value from the provided default Config
- **AND** `orchestrator_logger` defaults to the value of `logger` if not specified
- **AND** `csp_vault_logger` defaults to the value of `logger` if not specified

#### Scenario: Configuration validation
- **WHEN** configuration is loaded
- **THEN** `ConfigValidate::validate()` is called on the parsed configuration
- **AND** invalid configurations return a `ConfigError`

### Requirement: Temporary Configuration for Testing
The config system supports creating temporary configurations for testing.

#### Scenario: Temp config creation
- **WHEN** `Config::temp_config()` is called
- **THEN** a temporary directory is created with a prefix of `ic_config`
- **AND** a Config with default settings using that directory is returned
- **AND** the temporary directory is cleaned up when the returned `TempDir` is dropped

#### Scenario: Run with temp config
- **WHEN** `Config::run_with_temp_config()` is called with a closure
- **THEN** a temporary Config is created
- **AND** the closure is executed with the Config
- **AND** cleanup occurs automatically after the closure returns

### Requirement: Subnet Configuration
Subnet-specific execution parameters vary by subnet type to balance performance and resource usage.

#### Scenario: Instruction limits per message
- **WHEN** configuring execution limits
- **THEN** `MAX_INSTRUCTIONS_PER_MESSAGE` is 40 billion for application subnets
- **AND** `MAX_INSTRUCTIONS_PER_QUERY_MESSAGE` is 5 billion for queries
- **AND** system subnets multiply these limits by `SYSTEM_SUBNET_FACTOR` (10)

#### Scenario: Deterministic time slicing
- **WHEN** deterministic time slicing is enabled
- **THEN** `MAX_INSTRUCTIONS_PER_SLICE` is 2 billion, allowing approximately 1 second of execution per slice on a 2 GHz CPU
- **AND** `MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE` is also 2 billion for install_code operations
- **AND** `MAX_INSTRUCTIONS_PER_INSTALL_CODE` total is 300 billion, allowing large canister upgrades

#### Scenario: Round instruction limits
- **WHEN** configuring round limits
- **THEN** `MAX_INSTRUCTIONS_PER_ROUND` is 4 billion
- **AND** this is calibrated for approximately 1 block per second finalization rate
- **AND** short messages execute ~2B instructions per round; one long message can extend to 4B

#### Scenario: Heap delta limits
- **WHEN** configuring memory throughput
- **THEN** `MAX_HEAP_DELTA_PER_ITERATION` is 200MB based on 100MB/s memory throughput
- **AND** `HEAP_DELTA_INITIAL_RESERVE` is 32GiB for burst capacity after checkpoints
- **AND** `SUBNET_HEAP_DELTA_CAPACITY` defines the total heap delta capacity for the subnet

#### Scenario: Execution overhead accounting
- **WHEN** scheduling canister execution
- **THEN** `INSTRUCTION_OVERHEAD_PER_EXECUTION` is 2 million (approximately 1ms at 2 GHz)
- **AND** `INSTRUCTION_OVERHEAD_PER_CANISTER` is 8 million (approximately 4ms at 2 GHz)
- **AND** `INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION` is 12,000 per canister

### Requirement: Transport Configuration
Network transport settings for peer-to-peer communication.

#### Scenario: Transport config structure
- **WHEN** transport is configured
- **THEN** `TransportConfig` defines the listening address and port for peer connections

### Requirement: Cryptographic Configuration
Cryptographic component paths and settings.

#### Scenario: Crypto config
- **WHEN** crypto is configured
- **THEN** `CryptoConfig` specifies the crypto root directory
- **AND** directory permissions are verified via `check_dir_has_required_permissions`

### Requirement: State Manager Configuration
Configuration for the state persistence layer.

#### Scenario: State manager paths
- **WHEN** state manager is configured
- **THEN** the state directory path is specified for persisting checkpoints and canister state

### Requirement: Metrics Configuration
Configuration for the metrics collection and export system.

#### Scenario: Metrics exporter types
- **WHEN** metrics export is configured
- **THEN** the exporter can be `Http(SocketAddr)` for serving Prometheus metrics via HTTP
- **AND** other exporter types may be supported

### Requirement: Firewall Configuration
Configuration for the node firewall rules.

#### Scenario: Replica firewall config
- **WHEN** the replica firewall is configured
- **THEN** `ReplicaFirewallConfig` specifies the path to the firewall configuration file
- **AND** a default path of `FIREWALL_FILE_DEFAULT_PATH` is used if not specified
- **AND** if the default path is used, firewall management is disabled (test mode)

#### Scenario: Boundary node firewall config
- **WHEN** a boundary node firewall is configured
- **THEN** `BoundaryNodeFirewallConfig` provides separate firewall settings for boundary nodes

### Requirement: Registration Configuration
Configuration for node registration with the NNS.

#### Scenario: Registration config
- **WHEN** registration is configured
- **THEN** it includes the path to the node operator PEM file for signing registration requests

### Requirement: Artifact Pool Configuration
Configuration for the consensus artifact pool.

#### Scenario: Artifact pool paths
- **WHEN** the artifact pool is configured
- **THEN** `ArtifactPoolTomlConfig` specifies the consensus pool path and optional persistent pool backend
- **AND** the consensus pool directory is created on startup if it does not exist

### Requirement: Logger Configuration
Configuration for the replica logging system.

#### Scenario: Logger settings
- **WHEN** logging is configured via `LoggerConfig`
- **THEN** the log level, destination (stdout, stderr, or file), and format (JSON or text) are specified
- **AND** `block_on_overflow` controls whether logs block or drop when the async buffer is full

### Requirement: HTTP Handler Configuration
Configuration for the replica's HTTP endpoint.

#### Scenario: HTTP handler config
- **WHEN** the HTTP handler is configured
- **THEN** it specifies the listening address and port for accepting HTTP requests from users and other nodes

### Requirement: Adapters Configuration
Configuration for external service adapters.

#### Scenario: Adapters config
- **WHEN** adapters are configured
- **THEN** `AdaptersConfig` includes settings for Bitcoin adapter and HTTPS outcalls adapter connections

### Requirement: Flag Status
A generic flag type for enabling or disabling features.

#### Scenario: Flag status values
- **WHEN** a feature flag is configured
- **THEN** the `FlagStatus` enum can be `Enabled` or `Disabled`
- **AND** flags are used throughout the configuration for feature toggling

### Requirement: Initial IPv4 Configuration
Optional IPv4 network configuration for the node.

#### Scenario: IPv4 config
- **WHEN** IPv4 is configured
- **THEN** `IPv4Config` specifies the IPv4 address, gateway, and prefix length
- **AND** this configuration is optional (IPv6 is the primary network protocol)
