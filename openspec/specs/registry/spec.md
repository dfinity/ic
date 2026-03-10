# Registry

**Crates**: `ic-registry-canister-client`, `ic-registry-client-fake`, `ic-registry-nns-data-provider-wrappers`, `ic-registry-node-provider-rewards`, `ic-registry-proto-data-provider`, `ic-registry-replicator`, `ic-regedit`

The Registry is the configuration backbone of the Internet Computer (IC). It is a versioned key-value store implemented as an NNS canister that holds all system configuration: subnet membership, node records, replica versions, routing tables, firewall rules, cryptographic keys, and more. Every mutation increments the registry version atomically, and the full history of changes is maintained as an append-only changelog.

## Requirements

### Requirement: Versioned Key-Value Store

The registry stores key-value pairs where each mutation atomically increments a global version number. Values are protobuf-encoded and keyed by well-known string prefixes. The store supports insert, update, upsert, and delete mutation types with presence preconditions.

#### Scenario: Insert requires key absence
- **WHEN** an insert mutation is applied for a key
- **THEN** the key must not already exist in the registry
- **AND** an error is returned if the key is already present

#### Scenario: Update requires key presence
- **WHEN** an update mutation is applied for a key
- **THEN** the key must already exist in the registry
- **AND** an error is returned if the key is not present

#### Scenario: Upsert has no presence requirement
- **WHEN** an upsert mutation is applied for a key
- **THEN** the mutation succeeds regardless of whether the key exists or not

#### Scenario: Delete requires key presence
- **WHEN** a delete mutation is applied for a key
- **THEN** the key must already exist in the registry
- **AND** the value is removed (marked as deleted)

#### Scenario: Atomic mutate applies all mutations or none
- **WHEN** an atomic mutate request contains multiple mutations
- **THEN** all mutations are applied atomically as a single version increment
- **AND** if any precondition fails, none of the mutations are applied

#### Scenario: Version starts at zero for empty registry
- **WHEN** an empty registry is created
- **THEN** the latest version is zero (ZERO_REGISTRY_VERSION)

#### Scenario: Version increments on each mutation batch
- **WHEN** a batch of mutations is successfully applied
- **THEN** the registry version increments by exactly one

#### Scenario: Changelog versions are sequential
- **WHEN** the changelog is inspected
- **THEN** versions form a contiguous sequence starting from 1
- **AND** no version gaps exist between consecutive entries

### Requirement: Registry Certification

Registry updates are certified using hash trees so that clients can verify the authenticity and integrity of registry data without trusting any single node.

#### Scenario: Hash tree structure for certification
- **WHEN** the registry state is certified
- **THEN** a hash tree is constructed with `current_version` (LEB128-encoded) at the root
- **AND** a `delta` subtree containing big-endian encoded version numbers mapping to serialized protobuf changelog entries

#### Scenario: Certified data updated on each mutation
- **WHEN** a mutation is applied to the registry
- **THEN** the canister's certified data is recalculated from the root hash
- **AND** the root hash is a fork of the current_version tree and the changelog tree

#### Scenario: Clients verify certified responses
- **WHEN** a client receives a certified registry response
- **THEN** it verifies the threshold signature against the NNS subnet public key
- **AND** it verifies the certified data matches the hash tree reconstruction
- **AND** it verifies the canister ID is within the delegation's allowed range

### Requirement: Invariant Checks

Before any mutation is applied, the registry validates that the resulting state satisfies all global invariants. If any invariant check fails, the mutation is rejected.

#### Scenario: Invariant checks run before mutation application
- **WHEN** mutations are submitted via `maybe_apply_mutation_internal`
- **THEN** global state invariants are checked against the prospective new state
- **AND** the mutation is rejected (panics) if any invariant is violated

#### Scenario: Node operator invariants
- **WHEN** the registry state is validated
- **THEN** every node operator record must be well-formed

#### Scenario: Crypto key invariants
- **WHEN** the registry state is validated
- **THEN** every node must have valid cryptographic keys registered

#### Scenario: Node assignment invariants
- **WHEN** the registry state is validated
- **THEN** nodes are correctly assigned (not double-assigned across subnets)

#### Scenario: Routing table invariants
- **WHEN** the registry state is validated
- **THEN** the routing table must be well-formed with non-overlapping canister ID ranges

#### Scenario: Canister migration invariants
- **WHEN** the registry state is validated
- **THEN** all migrating canister ranges must be hosted by a subnet in their migration trace

#### Scenario: Subnet invariants
- **WHEN** the registry state is validated
- **THEN** subnet records are well-formed and consistent

#### Scenario: Replica version invariants
- **WHEN** the registry state is validated
- **THEN** all referenced replica versions exist in the blessed versions list

#### Scenario: API boundary node invariants
- **WHEN** the registry state is validated
- **THEN** API boundary node records are consistent

#### Scenario: HostOS version invariants
- **WHEN** the registry state is validated
- **THEN** HostOS version records are well-formed

#### Scenario: Endpoint invariants
- **WHEN** the registry state is validated
- **THEN** node endpoints are properly configured

#### Scenario: Firewall invariants
- **WHEN** the registry state is validated
- **THEN** firewall rule sets are well-formed

#### Scenario: Unassigned nodes config invariants
- **WHEN** the registry state is validated
- **THEN** the unassigned nodes configuration references a valid replica version

#### Scenario: Node record invariants
- **WHEN** the registry state is validated
- **THEN** node records are consistent and well-formed

### Requirement: Subnet Creation

New subnets are created through governance proposals. The creation process generates DKG key material, creates subnet records, and updates the routing table.

#### Scenario: Successful subnet creation
- **WHEN** a `CreateSubnetPayload` is submitted with valid node IDs
- **THEN** a new NI-DKG is performed via `setup_initial_dkg` on ic_00
- **AND** a new subnet record is inserted with the specified configuration
- **AND** a catch-up package contents record is created with DKG transcripts
- **AND** a threshold signing public key is stored for the new subnet
- **AND** the subnet is added to the global subnet list
- **AND** the routing table is updated to include the new subnet

#### Scenario: All nodes must exist
- **WHEN** a subnet creation payload references a non-existent node
- **THEN** the operation panics with "A NodeRecord for Node with id ... was not found"

#### Scenario: Nodes must not belong to another subnet
- **WHEN** a subnet creation payload includes nodes already assigned to a subnet
- **THEN** the operation panics with "Some Nodes are already members of Subnets"

#### Scenario: Nodes must not be API boundary nodes
- **WHEN** a subnet creation payload includes nodes assigned as API boundary nodes
- **THEN** the operation panics with "Some Nodes are already assigned as ApiBoundaryNode"

#### Scenario: Chain key configuration is validated
- **WHEN** a subnet creation payload includes chain key configuration
- **THEN** the referenced keys must exist in other subnets
- **AND** the specified source subnet must hold the requested key
- **AND** duplicate key IDs are rejected

#### Scenario: Subnet ID override
- **WHEN** a `subnet_id_override` is provided in the payload
- **THEN** the specified subnet ID is used instead of the generated one

### Requirement: Subnet Recovery

Stalled subnets can be recovered by updating their CatchUpPackageContents, optionally replacing broken nodes, and re-running DKG.

#### Scenario: Basic subnet recovery
- **WHEN** a `RecoverSubnetPayload` is submitted for a stalled subnet
- **THEN** a new DKG is performed with the current (or replacement) nodes
- **AND** the catch-up package contents are updated with new DKG transcripts
- **AND** the height, time, and state hash from the payload are set

#### Scenario: Recovery with node replacement
- **WHEN** a recovery payload includes `replacement_nodes`
- **THEN** the subnet membership is updated to use the replacement nodes
- **AND** the DKG is performed with the replacement nodes

#### Scenario: Recovery with registry store URI
- **WHEN** a recovery payload includes a `registry_store_uri`
- **THEN** the CUP is created with the registry store URI for NNS recovery
- **AND** no new DKG is performed

#### Scenario: Recovery with chain key reconfiguration
- **WHEN** a recovery payload includes `chain_key_config`
- **THEN** new chain key initializations are requested from source subnets
- **AND** keys removed from the subnet are disabled for signing
- **AND** the subnet record's chain key config is updated

#### Scenario: Cannot recover chain keys from self
- **WHEN** a recovery payload requests chain keys from the subnet being recovered
- **THEN** the operation panics with "Subnets cannot recover chain keys from themselves"

#### Scenario: Records must not change during async DKG call
- **WHEN** the subnet record, threshold signing key, or CUP changes during the DKG call
- **THEN** the operation panics to prevent inconsistent state

#### Scenario: Halt-at-CUP-height is handled
- **WHEN** a subnet has `halt_at_cup_height` set to true during recovery
- **THEN** `halt_at_cup_height` is reset to false
- **AND** `is_halted` is set to true (so it can be later unhalted)

### Requirement: Subnet Update

Subnet configuration can be updated through governance proposals, including parameters like ingress limits, replica versions, halting, and chain key configuration.

#### Scenario: Update subnet configuration
- **WHEN** an `UpdateSubnetPayload` is submitted
- **THEN** the specified fields are merged into the existing subnet record
- **AND** invariants are checked before applying

#### Scenario: Enable chain key signing
- **WHEN** `chain_key_signing_enable` is specified in the update payload
- **THEN** the subnet is added to the signing subnet list for the specified keys

#### Scenario: Disable chain key signing
- **WHEN** `chain_key_signing_disable` is specified in the update payload
- **THEN** the subnet is removed from the signing subnet list for the specified keys

#### Scenario: Chain keys cannot be deleted from subnet
- **WHEN** an update attempts to remove held chain keys from a subnet's configuration
- **THEN** the operation panics with "Chain keys cannot be deleted"

#### Scenario: Duplicate chain key IDs rejected
- **WHEN** an update payload contains duplicate chain key IDs
- **THEN** the operation panics with "have duplicates"

### Requirement: Node Registration

Nodes are added to the registry by node operators who have sufficient node allowances. Each node registration includes cryptographic keys, network endpoints, and association with a node operator.

#### Scenario: Successful node addition
- **WHEN** a valid `AddNodePayload` is submitted by a node operator
- **THEN** the node record is created with the specified network endpoints
- **AND** cryptographic keys (node signing, committee signing, DKG dealing encryption, TLS certificate, iDKG dealing encryption) are stored
- **AND** the node operator's allowance is decremented

#### Scenario: Node operator must have allowance
- **WHEN** a node operator with zero allowance tries to add a node
- **THEN** the operation is rejected

#### Scenario: IP address uniqueness
- **WHEN** a node is added with an IP address already in use
- **THEN** the operation is rejected to prevent IP conflicts

#### Scenario: Cryptographic key validation
- **WHEN** node keys are submitted during registration
- **THEN** the keys are validated for correctness and consistency

#### Scenario: Rate limiting for node additions
- **WHEN** a node operator or provider exceeds the rate limit (20 operations/day average)
- **THEN** the operation is rejected
- **AND** rate limits apply per node operator and per node provider independently
- **AND** IP-based rate limiting allows 1 node addition per day per IP address

### Requirement: Node Removal

Nodes can be removed from the registry, which deletes the node record, its cryptographic keys, and increments the node operator's allowance.

#### Scenario: Remove a single node
- **WHEN** a `RemoveNodesPayload` is submitted for an existing node
- **THEN** the node record is deleted
- **AND** all associated crypto key records are deleted
- **AND** the node operator's allowance is incremented by 1

#### Scenario: Remove multiple nodes from same operator
- **WHEN** multiple nodes owned by the same operator are removed
- **THEN** the node operator's allowance is incremented by the number of removed nodes
- **AND** only a single mutation is generated for the node operator record

#### Scenario: Cannot remove node in a subnet
- **WHEN** a removal is attempted for a node that is a member of a subnet
- **THEN** the operation panics with "Cannot remove a node that is a member of a subnet"

#### Scenario: Non-existent nodes are skipped
- **WHEN** a removal payload includes node IDs not in the registry
- **THEN** those nodes are silently skipped without error

#### Scenario: Duplicate node IDs are deduplicated
- **WHEN** a removal payload includes the same node ID multiple times
- **THEN** the node is removed only once and the allowance is incremented only once

### Requirement: Add Nodes to Subnet

Nodes can be added to existing subnets through governance proposals.

#### Scenario: Add nodes to subnet
- **WHEN** an `AddNodesToSubnetPayload` is submitted
- **THEN** the specified nodes are added to the subnet's membership list
- **AND** the subnet record is updated with the new membership

#### Scenario: Cannot add API boundary nodes
- **WHEN** nodes designated as API boundary nodes are added to a subnet
- **THEN** the operation panics with "Some Nodes are already assigned as ApiBoundaryNode"

### Requirement: Remove Nodes from Subnet

Nodes can be removed from their subnets through governance proposals.

#### Scenario: Remove nodes from subnet
- **WHEN** a `RemoveNodesFromSubnetPayload` is submitted
- **THEN** the specified nodes are removed from their respective subnet membership lists
- **AND** only subnet records that actually contained the removed nodes are updated

### Requirement: Node Swap in Subnet (Direct)

Node operators can directly swap nodes in subnets without governance proposals, subject to rate limiting and feature flags.

#### Scenario: Successful node swap
- **WHEN** a node operator submits a `SwapNodeInSubnetDirectlyPayload`
- **THEN** the old node is removed from the subnet membership
- **AND** the new node is added to the subnet membership
- **AND** the subnet size remains the same

#### Scenario: Feature must be enabled
- **WHEN** the node swapping feature is disabled globally
- **THEN** the operation fails with "Swapping feature is disabled on the network"

#### Scenario: Caller must be whitelisted
- **WHEN** the caller is not whitelisted for node swapping
- **THEN** the operation fails with "isn't whitelisted to use swapping feature yet"

#### Scenario: Subnet must allow swapping
- **WHEN** the target subnet does not have swapping enabled
- **THEN** the operation fails with "Swapping is disabled on subnet"

#### Scenario: Both nodes must be owned by same operator
- **WHEN** the old and new nodes have different node operators
- **THEN** the operation fails with "Both nodes must be owned by the same node operator"

#### Scenario: Caller must be the node operator
- **WHEN** the caller is not the node operator of the nodes
- **THEN** the operation fails with a caller/operator mismatch error

#### Scenario: New node must be unassigned
- **WHEN** the new node is already a member of a subnet
- **THEN** the operation fails with "is a member of subnet ... and cannot be used for direct swapping"

#### Scenario: Halted subnets disallow swapping
- **WHEN** the subnet is halted (likely under recovery)
- **THEN** the operation fails with "is halted and swapping is disabled"

#### Scenario: Subnet rate limiting (4 hour interval)
- **WHEN** a swap was performed on a subnet within the last 4 hours
- **THEN** the operation fails with a subnet rate limit error

#### Scenario: Node operator rate limiting per subnet (24 hour interval)
- **WHEN** the same node operator performed a swap on the same subnet within 24 hours
- **THEN** the operation fails with an operator rate limit error

### Requirement: Replica Version Management

The registry maintains a list of blessed (elected) replica versions. New versions can be elected and old versions can be retired through governance proposals.

#### Scenario: Elect a new replica version
- **WHEN** a `ReviseElectedGuestosVersionsPayload` elects a new version
- **THEN** a new `ReplicaVersionRecord` is inserted with release package URLs and SHA256 hash
- **AND** the version ID is added to the blessed replica versions list

#### Scenario: Retire replica versions
- **WHEN** versions are listed in `replica_versions_to_unelect`
- **THEN** the `ReplicaVersionRecord` entries are deleted
- **AND** the version IDs are removed from the blessed replica versions list

#### Scenario: Cannot retire version deployed to a subnet
- **WHEN** a version to be retired is currently used by any subnet
- **THEN** the operation panics with "Cannot retire versions ... because they are currently deployed to a subnet"

#### Scenario: Cannot retire version used by unassigned nodes
- **WHEN** a version to be retired is used by the unassigned nodes configuration
- **THEN** the operation panics with "Cannot retire version ... because it is currently deployed to unassigned nodes"

#### Scenario: Cannot elect and unelect same version
- **WHEN** the same version appears in both elect and unelect lists
- **THEN** the operation panics with "cannot elect and unelect the same version"

#### Scenario: Payload validation
- **WHEN** a payload elects a version
- **THEN** all of `replica_version_to_elect`, `release_package_sha256_hex`, and `release_package_urls` must be provided
- **AND** at least one version must be elected or unelected

### Requirement: Routing Table Management

The routing table maps canister ID ranges to subnets. It determines which subnet handles requests for a given canister.

#### Scenario: New subnet gets routing table allocation
- **WHEN** a new subnet is created
- **THEN** a canister ID range is assigned to it in the routing table (approximately 1M canister IDs)

#### Scenario: Reroute canister ranges
- **WHEN** a `RerouteCanisterRangesPayload` is submitted
- **THEN** the specified canister ID ranges are moved from the source to the destination subnet
- **AND** both source and destination must be known subnets
- **AND** the ranges must be currently assigned to the source subnet
- **AND** the rerouting must be covered by an existing canister migration entry

### Requirement: Canister Migration

Canister migration is a multi-step process: prepare (register migration intent), reroute (update routing table), and complete (clean up migration metadata).

#### Scenario: Prepare canister migration
- **WHEN** a `PrepareCanisterMigrationPayload` is submitted
- **THEN** the specified canister ID ranges are added to the canister_migrations record
- **AND** both subnets must be Application or VerifiedApplication type
- **AND** both subnets must have the same size
- **AND** both subnets must have the same type
- **AND** neither subnet can be a signing subnet (holding chain keys)
- **AND** all canisters must be hosted by the source subnet
- **AND** the canisters must not already be in an active migration

#### Scenario: Complete canister migration
- **WHEN** a `CompleteCanisterMigrationPayload` is submitted
- **THEN** the specified canister ID ranges are removed from canister_migrations
- **AND** the migration trace must match

#### Scenario: Rollback canister migration
- **WHEN** a reroute is submitted with a destination-to-source trace
- **THEN** the rerouting is allowed as a rollback of the migration

### Requirement: Firewall Rules Management

Firewall rules are managed per scope (global, replica nodes, API boundary nodes, subnet, or node) and can be added, removed, or updated through governance proposals.

#### Scenario: Add firewall rules
- **WHEN** an `AddFirewallRulesPayload` is submitted
- **THEN** the new rules are inserted at the specified positions in the ruleset
- **AND** the expected SHA-256 hash must match the resulting ruleset
- **AND** the number of positions must equal the number of rules

#### Scenario: Remove firewall rules
- **WHEN** a `RemoveFirewallRulesPayload` is submitted
- **THEN** the rules at the specified positions are removed from the ruleset
- **AND** the expected SHA-256 hash must match the resulting ruleset

#### Scenario: Update firewall rules
- **WHEN** an `UpdateFirewallRulesPayload` is submitted
- **THEN** the rules at the specified positions are replaced with the new rules
- **AND** the expected SHA-256 hash must match the resulting ruleset
- **AND** positions must be within bounds of the existing ruleset

#### Scenario: Firewall scopes
- **WHEN** firewall rules are managed
- **THEN** they can be scoped to Global, ReplicaNodes, ApiBoundaryNodes, a specific Subnet, or a specific Node

#### Scenario: Hash mismatch rejection
- **WHEN** the expected hash does not match the computed hash of the resulting ruleset
- **THEN** the operation panics with "Provided expected hash for new firewall ruleset does not match"

### Requirement: Node Operator Management

Node operators are entities authorized to add and remove nodes. They are associated with node providers and have limited node allowances.

#### Scenario: Add a new node operator
- **WHEN** an `AddNodeOperatorPayload` is submitted
- **THEN** a new `NodeOperatorRecord` is inserted in the registry
- **AND** the data center ID is stored in lowercase
- **AND** the record must have a unique node_operator_principal_id

#### Scenario: Update node operator configuration
- **WHEN** an `UpdateNodeOperatorConfigPayload` is submitted (via governance)
- **THEN** the specified fields of the node operator record are updated

#### Scenario: Update node operator configuration directly
- **WHEN** an `UpdateNodeOperatorConfigDirectlyPayload` is submitted by the node operator
- **THEN** the limited set of directly-modifiable fields are updated

#### Scenario: Remove node operators
- **WHEN** a `RemoveNodeOperatorsPayload` is submitted
- **THEN** the specified node operator records are deleted

### Requirement: Data Center Management

Data centers can be registered and removed from the registry.

#### Scenario: Add a data center
- **WHEN** a data center record is added
- **THEN** the ID is stored in lowercase
- **AND** the record must pass validation

#### Scenario: Cannot add duplicate data center
- **WHEN** a data center with an existing ID (case-insensitive) is added
- **THEN** the operation panics with "already exists"

#### Scenario: Remove and re-add data center
- **WHEN** a data center is removed and then re-added with the same ID
- **THEN** the operation succeeds

#### Scenario: Case-insensitive data center lookup
- **WHEN** a data center is looked up by ID
- **THEN** the lookup is case-insensitive (IDs are normalized to lowercase)

### Requirement: Provisional Whitelist

The provisional whitelist controls which principals can use the provisional (development) API.

#### Scenario: Clear provisional whitelist
- **WHEN** `do_clear_provisional_whitelist` is called
- **THEN** the whitelist is set to an empty set
- **AND** no principals are allowed to use the provisional API

#### Scenario: Whitelist modes
- **WHEN** the provisional whitelist is configured
- **THEN** it can be either `Set` (specific principals) or `All` (allow everyone)

### Requirement: Registry Client (Local Cache)

The registry client maintains a local cache of registry data, polling a data provider for updates. All reads are served from the cache and return immediately.

#### Scenario: Empty registry reports zero version
- **WHEN** a new registry client is created
- **THEN** `get_latest_version()` returns ZERO_REGISTRY_VERSION

#### Scenario: Polling updates the cache
- **WHEN** `poll_once()` is called
- **THEN** new records from the data provider are added to the cache
- **AND** the latest version is updated

#### Scenario: Version-aware value lookup
- **WHEN** `get_versioned_value(key, version)` is called
- **THEN** the most recent value for the key at or before the requested version is returned
- **AND** if no value exists, an empty record is returned
- **AND** if the version is beyond the latest known version, an error is returned

#### Scenario: Key family lookup
- **WHEN** `get_key_family(prefix, version)` is called
- **THEN** all keys with the given prefix that have non-empty values at the requested version are returned
- **AND** deleted keys (value is None) are excluded

#### Scenario: Background polling
- **WHEN** `fetch_and_start_polling()` is called
- **THEN** an initial synchronous poll is performed
- **AND** a background thread polls for updates at the configured POLLING_PERIOD
- **AND** the thread is stopped when the client is dropped

#### Scenario: Try polling for latest version
- **WHEN** `try_polling_latest_version(retries)` is called
- **THEN** poll_once is called repeatedly until the version stabilizes (same version seen twice)
- **AND** an error is returned if the version does not stabilize within the given retries

#### Scenario: Version timestamp tracking
- **WHEN** records are polled and cached
- **THEN** the timestamp of when each version was received is recorded
- **AND** `get_version_timestamp(version)` returns the time the version was first observed

### Requirement: Registry Transport

The registry transport layer handles serialization and deserialization of registry requests and responses using protobuf encoding.

#### Scenario: Get value request/response serialization
- **WHEN** a get_value request is serialized and deserialized
- **THEN** the key and optional version are preserved

#### Scenario: Get changes since request/response serialization
- **WHEN** a get_changes_since request is serialized and deserialized
- **THEN** the version and list of deltas are preserved

#### Scenario: Atomic mutate request/response serialization
- **WHEN** an atomic_mutate request is serialized and deserialized
- **THEN** all mutations and preconditions are preserved

#### Scenario: High capacity compatibility
- **WHEN** legacy RegistryAtomicMutateRequest is decoded as HighCapacityRegistryAtomicMutateRequest
- **THEN** the conversion succeeds (forward compatible)
- **AND** the reverse conversion also succeeds (backward compatible)

#### Scenario: Error types
- **WHEN** a registry operation fails
- **THEN** one of the defined error types is returned: MalformedMessage, KeyNotPresent, KeyAlreadyPresent, VersionNotLatest, VersionBeyondLatest, RegistryUnreachable, or UnknownError

### Requirement: High Capacity Storage (Chunking)

The registry supports storing large values by chunking them into smaller pieces stored in stable memory, enabling values larger than the inter-canister message limit.

#### Scenario: Small mutations are not chunked
- **WHEN** a mutation's encoded size is below MIN_CHUNKABLE_ATOMIC_MUTATION_LEN (~1.3 MB)
- **THEN** the mutation is stored as-is without chunking

#### Scenario: Large mutations are chunked
- **WHEN** a mutation's encoded size exceeds MIN_CHUNKABLE_ATOMIC_MUTATION_LEN but is under MAX_CHUNKABLE_ATOMIC_MUTATION_LEN (10 MB)
- **THEN** large blob values are stored in the CHUNKS stable memory
- **AND** the mutation references chunk keys instead of inline values

#### Scenario: Excessively large mutations are rejected
- **WHEN** a mutation's encoded size exceeds MAX_CHUNKABLE_ATOMIC_MUTATION_LEN (10 MB)
- **THEN** the operation panics with "Mutation too large"

#### Scenario: Response size limiting
- **WHEN** registry deltas are returned in a response
- **THEN** the total size is capped at MAX_REGISTRY_DELTAS_SIZE (approximately 2/3 of MAX_INTER_CANISTER_PAYLOAD_IN_BYTES)

### Requirement: Registry Local Store

The local store persists registry changelog entries to disk as protobuf files, one per version, enabling offline access and node bootstrapping.

#### Scenario: Store changelog entry
- **WHEN** a changelog entry is stored for a version
- **THEN** the entry is written as a protobuf file
- **AND** for version > 1, the previous version's entry must already exist

#### Scenario: Get changelog since version
- **WHEN** `get_changelog_since_version(v)` is called
- **THEN** all changelog entries after version v are returned in order

#### Scenario: Clear local store
- **WHEN** `clear()` is called on the local store
- **THEN** all stored registry versions are removed

### Requirement: NNS Data Provider Certification

The NNS data provider validates certified responses from the registry canister by verifying threshold signatures and hash tree consistency.

#### Scenario: Valid certified response
- **WHEN** a certified response is received and verified
- **THEN** the threshold signature is valid against the NNS subnet key
- **AND** the certified data matches the hash tree
- **AND** the canister ID is within the delegated range

#### Scenario: Certification error types
- **WHEN** certification fails
- **THEN** one of the defined errors is returned: DeserError, InvalidSignature, CertifiedDataMismatch, InvalidDeltas, MalformedHashTree, MultipleSubnetDelegationsNotAllowed, CanisterIdOutOfRange, SubnetIdMismatch, or DechunkifyingFailed

### Requirement: Registry Canister Access Control

The registry canister enforces access control on its update methods based on the caller's identity.

#### Scenario: Governance-only methods
- **WHEN** a governance-only method (create_subnet, recover_subnet, update_subnet, add_node_operator, etc.) is called
- **THEN** the caller must be the Governance canister
- **AND** the call is rejected if the caller is any other principal

#### Scenario: Migration canister methods
- **WHEN** canister migration methods are called
- **THEN** the caller must be the Migration canister

#### Scenario: Node operator direct methods
- **WHEN** direct methods (swap_node_in_subnet_directly, update_node_operator_config_directly, add_node) are called
- **THEN** the caller is verified against the appropriate authorization (node operator ownership)

### Requirement: Subnet Operational Level

Subnets can have their operational level set to control whether they are in normal operation or down for repairs.

#### Scenario: Set subnet operational level
- **WHEN** a `SetSubnetOperationalLevelPayload` is submitted
- **THEN** the subnet record is updated with the new operational level (normal or down_for_repairs)
- **AND** SSH access and recalled replica version IDs can be configured

### Requirement: Registry Key Structure

All registry keys follow a well-defined naming convention using string prefixes that allow efficient key family lookups.

#### Scenario: Subnet keys
- **WHEN** subnet-related keys are constructed
- **THEN** subnet records use prefix `subnet_record_`
- **AND** the subnet list uses key `subnet_list`
- **AND** the NNS subnet ID uses key `nns_subnet_id`

#### Scenario: Node keys
- **WHEN** node-related keys are constructed
- **THEN** node records use prefix `node_record_`
- **AND** node operator records use prefix `node_operator_record_`
- **AND** API boundary nodes use prefix `api_boundary_node_`

#### Scenario: Crypto keys
- **WHEN** crypto-related keys are constructed
- **THEN** crypto records use prefix `crypto_record_` with node ID and key purpose
- **AND** TLS certificates use prefix `crypto_tls_cert_`
- **AND** threshold signing keys use prefix `crypto_threshold_signing_public_key_`

#### Scenario: Version keys
- **WHEN** version-related keys are constructed
- **THEN** replica versions use prefix `replica_version_`
- **AND** HostOS versions use prefix `hostos_version_`
- **AND** blessed versions use key `blessed_replica_versions`

#### Scenario: Routing and migration keys
- **WHEN** routing-related keys are constructed
- **THEN** the routing table uses key `routing_table`
- **AND** canister migrations use key `canister_migrations`
- **AND** canister ranges use prefix `canister_ranges_` with hex-encoded canister ID

#### Scenario: Firewall keys
- **WHEN** firewall rule keys are constructed
- **THEN** they use prefix `firewall_rules_` followed by scope (global, replica_nodes, api_boundary_nodes, subnet_{id}, node_{id})

#### Scenario: Other keys
- **WHEN** other registry keys are constructed
- **THEN** the provisional whitelist uses key `provisional_whitelist`
- **AND** data centers use prefix `data_center_record_`
- **AND** the node rewards table uses key `node_rewards_table`
- **AND** the unassigned nodes config uses key `unassigned_nodes_config`
- **AND** chain key enabled subnet lists use prefix `master_public_key_id_`
- **AND** catch-up package contents use prefix `catch_up_package_contents_`

### Requirement: Deploy GuestOS to Subnet Nodes

All nodes in a subnet can be upgraded to a new GuestOS version through a governance proposal.

#### Scenario: Deploy to all subnet nodes
- **WHEN** a `DeployGuestosToAllSubnetNodesPayload` is submitted
- **THEN** the subnet record's replica_version_id is updated to the new version
- **AND** the new version must be in the list of blessed replica versions

### Requirement: Deploy GuestOS to Unassigned Nodes

Unassigned nodes (not part of any subnet) can be upgraded to a new GuestOS version.

#### Scenario: Deploy to unassigned nodes
- **WHEN** a `DeployGuestosToAllUnassignedNodesPayload` is submitted
- **THEN** the unassigned nodes configuration is updated with the new replica version

### Requirement: HostOS Version Management

HostOS versions are managed separately from GuestOS/replica versions and can be elected, deployed to specific nodes, or updated.

#### Scenario: Elect HostOS versions
- **WHEN** a `ReviseElectedHostosVersionsPayload` is submitted
- **THEN** new HostOS versions can be added to or removed from the elected list

#### Scenario: Deploy HostOS to specific nodes
- **WHEN** a `UpdateNodesHostosVersionPayload` is submitted
- **THEN** the specified nodes' HostOS version is updated

### Requirement: Subnet Admins

Subnets may designate a list of principal IDs as administrators with additional operational privileges. Subnet admin assignments are managed through registry mutations.

#### Scenario: Store subnet admins in registry
- **WHEN** subnet configuration is stored in the registry
- **THEN** a `subnet_admins` field contains an optional vector of principal IDs
- **AND** the field is persisted across canister upgrades

#### Scenario: Update subnet admins
- **WHEN** an `UpdateSubnetAdminsPayload` is submitted
- **THEN** the target subnet's admin list is updated
- **AND** the registry version is incremented
- **AND** the change is reflected in subsequent registry queries

#### Scenario: Admin list validation
- **WHEN** a subnet's admin list is updated
- **THEN** the new list is validated for correctness
- **AND** duplicate principals in the admin list are rejected if applicable

#### Scenario: Subnet admins are optional
- **WHEN** a subnet has no designated admins
- **THEN** the `subnet_admins` field is `None` or empty
- **AND** no special privileges are granted

#### Scenario: Admin access control
- **WHEN** admin-only subnet operations are checked (e.g., certain configuration changes)
- **THEN** the caller's principal is checked against the subnet's admin list
- **AND** operations are rejected if the caller is not in the list

### Requirement: Change Subnet Membership

Subnet membership can be changed by simultaneously adding and removing nodes in a single operation.

#### Scenario: Change membership atomically
- **WHEN** a `ChangeSubnetMembershipPayload` is submitted
- **THEN** the specified nodes are added to and removed from the subnet in a single mutation
