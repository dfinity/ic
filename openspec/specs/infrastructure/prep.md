# Prep (IC Preparation Tools)

The ic-prep tool generates the initial configuration files needed to bootstrap an Internet Computer instance. It produces the registry local store, initial DKG transcripts, routing tables, and other artifacts required for genesis.

## Requirements

### Requirement: Topology Configuration
The preparation tool defines the network topology as a collection of subnets, unassigned nodes, and API boundary nodes.

#### Scenario: Subnet configuration
- **WHEN** a topology is defined via `TopologyConfig`
- **THEN** subnets are indexed by `SubnetIndex` (u64)
- **AND** each subnet has a `SubnetConfig` defining its membership, parameters, and features
- **AND** unassigned nodes and API boundary nodes are tracked separately

#### Scenario: Subnet membership
- **WHEN** a subnet is configured
- **THEN** its `membership` maps `NodeIndex` to `NodeConfiguration`
- **AND** each node has connection endpoints, node operator principal, and crypto keys

#### Scenario: Subnet parameters
- **WHEN** a subnet's execution parameters are configured
- **THEN** `SubnetConfig` includes: max ingress bytes per message, max ingress messages per block, max ingress bytes per block, max block payload size, subnet type, and initial running state (Active or Halted)

### Requirement: Routing Table Generation
The preparation tool generates the initial routing table that maps canister ID ranges to subnets.

#### Scenario: Routing table with specified IDs allocation
- **WHEN** the routing table is generated
- **THEN** each subnet gets a canister ID range for specified IDs
- **AND** the first subnet additionally gets a subnets allocation range
- **AND** the allocation range starts after the specified IDs range with a gap of one `CANISTER_IDS_PER_SUBNET`

### Requirement: Registry Local Store Generation
The preparation tool generates the initial registry local store that nodes read on first boot.

#### Scenario: Registry local store creation
- **WHEN** the IC is initialized
- **THEN** a registry local store is created at `IC_REGISTRY_LOCAL_STORE_PATH` ("ic_registry_local_store")
- **AND** the initial registry version is `INITIAL_REGISTRY_VERSION` (version 1)
- **AND** all registry mutations are written as a changelog to the local store

#### Scenario: Registry entries generated
- **WHEN** the registry local store is populated
- **THEN** it contains entries for:
  - Root subnet ID
  - Subnet list record
  - Subnet records with DKG transcripts and CUP contents
  - Node records with connection endpoints
  - Node operator records
  - Replica version records (blessed versions)
  - Routing table
  - Provisional whitelist
  - Firewall rules
  - Unassigned nodes configuration
  - Data center records
  - API boundary node records

### Requirement: Initial DKG Transcript Generation
Each subnet requires initial Distributed Key Generation (DKG) transcripts for threshold signatures.

#### Scenario: DKG transcript creation
- **WHEN** a subnet is initialized
- **THEN** initial NiDKG transcripts are generated for both `LowThreshold` and `HighThreshold` tags
- **AND** the transcripts are embedded in the `CatchUpPackageContents` for the subnet
- **AND** the subnet's threshold signing public key is derived from the transcripts

### Requirement: Node Initialization
Each node in the topology is initialized with cryptographic keys and connection information.

#### Scenario: Node configuration
- **WHEN** a node is initialized
- **THEN** a `NodeConfiguration` specifies: connection endpoints (xnet, public), the node operator principal, and secret key store
- **AND** an `InitializedNode` contains the node ID and generated crypto keys

#### Scenario: Node ID derivation
- **WHEN** a node is initialized
- **THEN** the node ID is derived from the node's cryptographic public keys

### Requirement: Subnet Initialization
Each subnet is initialized with membership, DKG transcripts, and a genesis CUP.

#### Scenario: Initialized subnet
- **WHEN** a subnet is initialized
- **THEN** an `InitializedSubnet` contains: subnet ID, subnet record, initialized node map, subnet threshold signing public key, and CUP contents

#### Scenario: Initial CUP contents
- **WHEN** CUP contents are generated for a subnet
- **THEN** the CUP contains initial DKG transcript records for both threshold levels
- **AND** the height is set to 0 (genesis)
- **AND** no state hash is present (fresh start)

### Requirement: State Directory Preparation
The preparation tool can create a complete state directory for bootstrapping a node.

#### Scenario: State directory creation
- **WHEN** `prep_state_directory` is called
- **THEN** it creates the directory structure needed for a node to boot
- **AND** the registry local store is written to the appropriate path
- **AND** the NNS public key is written as a PEM file

### Requirement: Root Public Key Export
The preparation tool exports the NNS root public key for verification by clients.

#### Scenario: Root public key PEM
- **WHEN** the IC is initialized
- **THEN** the NNS subnet's threshold signing public key is exported as `nns_public_key.pem`
- **AND** the key is in DER format encoded as PEM

### Requirement: Replica Version Registration
The preparation tool registers the initial replica version in the registry.

#### Scenario: Blessed replica version
- **WHEN** the initial registry is created
- **THEN** a `ReplicaVersionRecord` is created for the initial version
- **AND** the version is added to `BlessedReplicaVersions`
- **AND** optional `GuestLaunchMeasurements` can be included for attestation

#### Scenario: Unassigned nodes config
- **WHEN** unassigned nodes exist in the topology
- **THEN** an `UnassignedNodesConfigRecord` is created
- **AND** it specifies the replica version that unassigned nodes should run

### Requirement: Firewall Rules Initialization
The preparation tool sets up initial firewall rules in the registry.

#### Scenario: Initial firewall rules
- **WHEN** the registry is initialized
- **THEN** default firewall rules are created for the `FirewallRulesScope`
- **AND** rules define allowed ports, protocols, and directions (ingress/egress)
- **AND** `FirewallAction` can be Allow or Deny

### Requirement: Data Center Registration
The preparation tool registers data centers in the registry.

#### Scenario: Data center records
- **WHEN** data centers are configured
- **THEN** `DataCenterRecord` entries are created with GPS coordinates and region information
- **AND** data centers are associated with node operators

### Requirement: Node Operator Registration
The preparation tool registers node operators who manage nodes.

#### Scenario: Node operator records
- **WHEN** node operators are configured
- **THEN** `NodeOperatorRecord` entries are created with allowances
- **AND** the initial allowance is `INITIAL_NODE_ALLOWANCE_MULTIPLIER` (40) times the number of initial nodes
- **AND** node operator principals are associated with their managed nodes

### Requirement: Provisional Whitelist
The preparation tool configures the provisional whitelist for canister creation.

#### Scenario: Provisional whitelist setup
- **WHEN** the registry is initialized
- **THEN** a `ProvisionalWhitelist` is created
- **AND** it controls which principals can create canisters during the provisional period

### Requirement: Principal ID Tool
A utility binary for working with principal IDs.

#### Scenario: Principal ID operations
- **WHEN** the `principal_id` binary is invoked
- **THEN** it provides utilities for converting between different principal ID representations
