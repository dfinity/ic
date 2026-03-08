# Registry Client Infrastructure Specification

This specification covers the registry client-side crates that provide local access to IC registry data. These crates collectively enable replicas, tools, and tests to read typed registry records from an in-memory cache backed by various data providers (NNS canister, local file store, or in-memory test data). The infrastructure spans the core client with caching and polling, helper traits for typed deserialization, key formatting utilities, a file-backed local store, in-process local registry, routing table data structures, subnet feature flags and type enumerations, NNS data providers, transport/proto definitions, a CLI registry editor, provisional whitelist management, and fake/test utilities.

---

## Crate: `ic-registry-client` (`rs/registry/client`)

Implements `RegistryClient` from `ic-interfaces-registry`. Wraps a `RegistryDataProvider` with an in-memory cache and optional background polling thread. All reads return immediately from the cache.

### Requirement: Registry Client Creation and Initialization

A `RegistryClientImpl` is created with a data provider and optional metrics registry. It starts with an empty cache at version zero.

#### Scenario: Create client with data provider
- **WHEN** `RegistryClientImpl::new` is called with a data provider and optional metrics registry
- **THEN** a new client is returned with an empty cache at `ZERO_REGISTRY_VERSION`
- **AND** no background polling thread is running
- **AND** `get_latest_version()` returns `ZERO_REGISTRY_VERSION`

#### Scenario: Fetch and start polling
- **WHEN** `fetch_and_start_polling` is called on a client
- **THEN** `poll_once` is called synchronously to fetch the initial state
- **AND** a background thread named `"RegistryClient_Thread"` is spawned that polls every `POLLING_PERIOD` (5 seconds)
- **AND** the background thread is stopped when the client is dropped (via `JoinOnDrop`)

#### Scenario: Double call to fetch_and_start_polling fails
- **WHEN** `fetch_and_start_polling` is called a second time on the same client
- **THEN** a `PollLockFailed` error is returned with the message `"'fetch_and_start_polling' already called"`
- **AND** the existing polling thread continues unchanged

### Requirement: Polling and Cache Updates

The client polls its data provider for updates since the latest cached version. New records are merged into the sorted cache under a write lock with version monotonicity enforcement.

#### Scenario: poll_once fetches new records
- **WHEN** `poll_once` is called and the data provider returns records newer than the cached version
- **THEN** the cache is updated with the new records via binary search insertion (maintaining sort order by `(key, version)`)
- **AND** the `latest_version` in the cache advances to the maximum version among the new records
- **AND** a timestamp is recorded for each new version
- **AND** the `ic_registry_client_registry_version` metric is set to the new version

#### Scenario: poll_once with no new data
- **WHEN** `poll_once` is called and the data provider returns an empty record set
- **THEN** the cache remains unchanged
- **AND** `Ok(())` is returned

#### Scenario: poll_once with data provider error
- **WHEN** `poll_once` is called and the data provider returns an error
- **THEN** the error is propagated as a `RegistryClientError::DataProviderQueryFailed`
- **AND** the cache remains unchanged

#### Scenario: Concurrent poll_once calls are safe
- **WHEN** multiple threads call `poll_once` concurrently
- **THEN** the write lock on the cache ensures only one update proceeds at a time
- **AND** the version check under the write lock prevents stale updates from being applied

#### Scenario: try_polling_latest_version converges
- **WHEN** `try_polling_latest_version(retries)` is called
- **THEN** it calls `poll_once` repeatedly until `get_latest_version` returns the same value for two consecutive polls
- **AND** it returns `Ok(())` when convergence is reached
- **AND** timeout errors from the data provider are retried silently

#### Scenario: try_polling_latest_version exhausts retries
- **WHEN** `try_polling_latest_version(retries)` is called and the version keeps advancing through all retries
- **THEN** a `PollingLatestVersionFailed { retries }` error is returned

### Requirement: Versioned Value Queries

Reads from the client are served from the local cache using binary search. Querying a version beyond the latest cached version is an error.

#### Scenario: Query at a known version with exact match
- **WHEN** `get_versioned_value(key, version)` is called and a record exists at exactly that version for the key
- **THEN** the record at that exact version is returned
- **AND** the call returns immediately with no network I/O

#### Scenario: Query at a known version with earlier record
- **WHEN** `get_versioned_value(key, version)` is called and the key was last set at a version earlier than the queried version
- **THEN** the most recent record for the key with version <= the queried version is returned

#### Scenario: Query for a nonexistent key
- **WHEN** `get_versioned_value(key, version)` is called for a key that was never set
- **THEN** an empty record with `ZERO_REGISTRY_VERSION` and `value: None` is returned

#### Scenario: Query at version zero
- **WHEN** `get_versioned_value(key, ZERO_REGISTRY_VERSION)` is called
- **THEN** an empty record is returned for any key
- **AND** this holds regardless of what data has been cached

#### Scenario: Query at a version beyond the cache
- **WHEN** `get_versioned_value(key, version)` is called with a version greater than the latest cached version
- **THEN** a `VersionNotAvailable { version }` error is returned

#### Scenario: Deleted keys return None
- **WHEN** a key is set at version `v1` and then deleted (value set to `None`) at version `v2 > v1`
- **THEN** `get_value(key, v1)` returns `Some(bytes)`
- **AND** `get_value(key, v2)` returns `None`
- **AND** `get_value(key, v3)` for `v3 > v2` also returns `None` (deletion persists)

### Requirement: Key Family Queries

The client supports prefix-based queries to enumerate all keys sharing a common prefix.

#### Scenario: Get key family at version
- **WHEN** `get_key_family(key_prefix, version)` is called
- **THEN** all keys starting with `key_prefix` that have a non-`None` value at the given version are returned
- **AND** deleted keys (value is `None`) are excluded from the result
- **AND** the result contains no duplicates

#### Scenario: Key family at version zero
- **WHEN** `get_key_family(key_prefix, ZERO_REGISTRY_VERSION)` is called
- **THEN** an empty list is returned

#### Scenario: Key family tracks deletions
- **WHEN** a key matching the prefix is added at version `v1` and deleted at version `v2`
- **THEN** the key appears in the family at `v1` but not at `v2` or later

### Requirement: Version Timestamp Tracking

The client records the local wall-clock time when each version becomes available.

#### Scenario: Get version timestamp
- **WHEN** `get_version_timestamp(version)` is called for a version that was polled
- **THEN** the time at which that version was first cached locally is returned

#### Scenario: Timestamp for unknown version
- **WHEN** `get_version_timestamp(version)` is called for a version not in the cache
- **THEN** `None` is returned

---

## Crate: `ic-registry-client-helpers` (`rs/registry/helpers`)

Provides convenience traits that wrap a `RegistryClient` and deserialize raw registry bytes into typed Rust structures. Each helper trait is blanket-implemented for all types implementing `RegistryClient`.

### Requirement: Registry Value Deserialization

The core `deserialize_registry_value` function converts raw bytes from the registry client into typed protobuf values.

#### Scenario: Deserialize valid protobuf bytes
- **WHEN** `deserialize_registry_value::<T>` is called with `Ok(Some(bytes))` containing valid protobuf
- **THEN** the decoded value of type `T` is returned as `Ok(Some(value))`

#### Scenario: Deserialize with missing value
- **WHEN** `deserialize_registry_value::<T>` is called with `Ok(None)`
- **THEN** `Ok(None)` is returned

#### Scenario: Deserialize with invalid bytes
- **WHEN** `deserialize_registry_value::<T>` is called with bytes that cannot be decoded as type `T`
- **THEN** a `DecodeError` is returned with a message describing the deserialization failure

### Requirement: Subnet Registry Helpers (`SubnetRegistry` trait)

Typed access to subnet records, membership, configuration, and operational state.

#### Scenario: Get subnet record
- **WHEN** `get_subnet_record(subnet_id, version)` is called
- **THEN** the `SubnetRecord` protobuf is fetched using key `"subnet_record_<subnet_id>"`
- **AND** deserialized into a `SubnetRecord`

#### Scenario: Get root subnet ID
- **WHEN** `get_root_subnet_id(version)` is called
- **THEN** the value at key `"nns_subnet_id"` is fetched and decoded as a `SubnetId`

#### Scenario: Get node IDs on subnet
- **WHEN** `get_node_ids_on_subnet(subnet_id, version)` is called
- **THEN** the subnet record is fetched and the `membership` field is parsed into `Vec<NodeId>`

#### Scenario: Get subnet size
- **WHEN** `get_subnet_size(subnet_id, version)` is called
- **THEN** the length of the `membership` field in the subnet record is returned

#### Scenario: Get ingress message settings
- **WHEN** `get_ingress_message_settings(subnet_id, version)` is called
- **THEN** `max_ingress_bytes_per_message`, `max_ingress_messages_per_block`, and `max_ingress_bytes_per_block` are extracted from the subnet record
- **AND** if `max_ingress_bytes_per_block` is 0, the default from `ic_limits::MAX_INGRESS_BYTES_PER_BLOCK` is used

#### Scenario: Get subnet features
- **WHEN** `get_features(subnet_id, version)` is called
- **THEN** the `features` field of the subnet record is deserialized into `SubnetFeatures`

#### Scenario: Get chain key config
- **WHEN** `get_chain_key_config(subnet_id, version)` is called
- **THEN** the `chain_key_config` field of the subnet record is deserialized into `ChainKeyConfig`

#### Scenario: Get notarization delay settings
- **WHEN** `get_notarization_delay_settings(subnet_id, version)` is called
- **THEN** `unit_delay` and `initial_notary_delay` durations are extracted from the subnet record

#### Scenario: Get DKG interval length
- **WHEN** `get_dkg_interval_length(subnet_id, version)` is called
- **THEN** the `dkg_interval_length` from the subnet record is returned as `Height`

#### Scenario: Get halt status
- **WHEN** `get_is_halted(subnet_id, version)` is called
- **THEN** the `is_halted` boolean from the subnet record is returned

#### Scenario: Get halt at CUP height
- **WHEN** `get_halt_at_cup_height(subnet_id, version)` is called
- **THEN** the `halt_at_cup_height` boolean from the subnet record is returned

#### Scenario: Get replica version
- **WHEN** `get_replica_version(subnet_id, version)` is called
- **THEN** the `replica_version_id` from the subnet record is parsed into a `ReplicaVersion`

#### Scenario: Get replica version record
- **WHEN** `get_replica_version_record(subnet_id, version)` is called
- **THEN** the subnet record is fetched to get the `replica_version_id`
- **AND** the corresponding `ReplicaVersionRecord` is fetched using key `"replica_version_<id>"`

#### Scenario: Get subnet type
- **WHEN** `get_subnet_type(subnet_id, version)` is called
- **THEN** the `subnet_type()` of the subnet record is returned as a `SubnetType` protobuf enum

#### Scenario: Get CUP contents
- **WHEN** `get_cup_contents(subnet_id, version)` is called
- **THEN** the `CatchUpPackageContents` is fetched from key `"catch_up_package_contents_<subnet_id>"`
- **AND** the versioned record includes the registry version at which the value was last written

#### Scenario: Get listed subnet for node ID
- **WHEN** `get_listed_subnet_for_node_id(node_id, version)` is called
- **THEN** all listed subnet records are scanned for one containing the node
- **AND** the `(SubnetId, SubnetRecord)` pair is returned, or `None` if not found

### Requirement: Subnet List Registry Helpers (`SubnetListRegistry` trait)

Access to the list of subnets in the current IC topology.

#### Scenario: Get subnet IDs
- **WHEN** `get_subnet_ids(version)` is called
- **THEN** the `SubnetListRecord` is fetched from key `"subnet_list"`
- **AND** the subnet IDs are parsed from the protobuf and returned as `Vec<SubnetId>`

#### Scenario: Get system subnet IDs
- **WHEN** `get_system_subnet_ids(version)` is called
- **THEN** all subnet IDs are fetched and filtered to include only those with `SubnetType::System`

### Requirement: Node Registry Helpers (`NodeRegistry` trait)

Typed access to node records and node-to-subnet lookups.

#### Scenario: Get node record
- **WHEN** `get_node_record(node_id, version)` is called
- **THEN** the `NodeRecord` protobuf is fetched using key `"node_record_<node_id>"`

#### Scenario: Get subnet ID from node ID
- **WHEN** `get_subnet_id_from_node_id(node_id, version)` is called
- **THEN** all subnet membership lists are scanned
- **AND** the `SubnetId` of the subnet containing the node is returned, or `None` if unassigned

#### Scenario: Get all node IDs
- **WHEN** `get_node_ids(version)` is called
- **THEN** all keys with prefix `"node_record_"` are enumerated via `get_key_family`
- **AND** the node IDs are parsed from the key suffixes

### Requirement: Subnet Transport Registry Helpers (`SubnetTransportRegistry` trait)

Access to node records for all nodes on a subnet, used by transport/p2p layers.

#### Scenario: Get subnet node records
- **WHEN** `get_subnet_node_records(subnet_id, version)` is called
- **THEN** the subnet membership is fetched, then each node's `NodeRecord` is retrieved
- **AND** a list of `(NodeId, NodeRecord)` pairs is returned
- **AND** `Ok(None)` is returned if the subnet record or any node record is missing

### Requirement: Crypto Registry Helpers (`CryptoRegistry` trait)

Typed access to cryptographic keys and certificates stored in the registry.

#### Scenario: Get crypto key for node
- **WHEN** `get_crypto_key_for_node(node_id, key_purpose, version)` is called
- **THEN** the public key protobuf is fetched using key `"crypto_record_<node_id>_<key_purpose>"`

#### Scenario: Get threshold signing public key for subnet
- **WHEN** `get_threshold_signing_public_key_for_subnet(subnet_id, version)` is called
- **THEN** the key is fetched using `"crypto_threshold_signing_public_key_<subnet_id>"`
- **AND** the protobuf is converted to a `ThresholdSigPublicKey`

#### Scenario: Get TLS certificate
- **WHEN** `get_tls_certificate(node_id, version)` is called
- **THEN** the `X509PublicKeyCert` is fetched using key `"crypto_tls_cert_<node_id>"`

#### Scenario: Get initial DKG transcripts
- **WHEN** `get_initial_dkg_transcripts(subnet_id, version)` is called
- **THEN** the `CatchUpPackageContents` is fetched
- **AND** the low-threshold and high-threshold NI-DKG transcripts are deserialized
- **AND** a `DecodeError` is returned if either transcript is missing

### Requirement: Routing Table Registry Helpers (`RoutingTableRegistry` trait)

Access to the routing table and canister migration records.

#### Scenario: Get routing table
- **WHEN** `get_routing_table(version)` is called
- **THEN** all keys with prefix `"canister_ranges_"` are fetched and deserialized into routing table shards
- **AND** the shards are assembled into a `RoutingTable`
- **AND** `Ok(None)` is returned if no canister range keys exist

#### Scenario: Get subnet canister ranges
- **WHEN** `get_subnet_canister_ranges(version, subnet_id)` is called
- **THEN** only ranges assigned to the given `subnet_id` are extracted from the routing table

#### Scenario: Get canister migrations
- **WHEN** `get_canister_migrations(version)` is called
- **THEN** the canister migrations record is fetched from key `"canister_migrations"`

### Requirement: Firewall Registry Helpers (`FirewallRegistry` trait)

Access to firewall rules and node IP addresses for firewall management.

#### Scenario: Get firewall rules by scope
- **WHEN** `get_firewall_rules(version, scope)` is called with a `FirewallRulesScope`
- **THEN** the `FirewallRuleSet` is fetched using key `"firewall_rules_<scope>"`

#### Scenario: Get all nodes IP addresses
- **WHEN** `get_all_nodes_ip_addresses(version)` is called
- **THEN** all node records are enumerated and their HTTP and xnet endpoint IP addresses are collected
- **AND** duplicate addresses are removed

#### Scenario: Get system subnet nodes IP addresses
- **WHEN** `get_system_subnet_nodes_ip_addresses(version)` is called
- **THEN** only nodes belonging to system-type subnets have their IP addresses returned

#### Scenario: Get app subnet nodes IP addresses
- **WHEN** `get_app_subnet_nodes_ip_addresses(version)` is called
- **THEN** only nodes belonging to non-system subnets have their IP addresses returned

### Requirement: API Boundary Node Registry Helpers (`ApiBoundaryNodeRegistry` trait)

Access to API boundary node records and their system/app split.

#### Scenario: Get API boundary node IDs
- **WHEN** `get_api_boundary_node_ids(version)` is called
- **THEN** all keys with prefix `"api_boundary_node_"` are enumerated
- **AND** the node IDs are parsed from the key suffixes

#### Scenario: Get API boundary node record
- **WHEN** `get_api_boundary_node_record(node_id, version)` is called
- **THEN** the `ApiBoundaryNodeRecord` is fetched using key `"api_boundary_node_<node_id>"`

#### Scenario: System and app boundary node split
- **WHEN** `get_system_api_boundary_node_ids(version)` is called
- **THEN** all API boundary node IDs are sorted
- **AND** the first `ceil(n/2)` nodes are returned as system boundary nodes
- **AND** `get_app_api_boundary_node_ids(version)` returns the remaining nodes

### Requirement: Blessed Replica Version Registry Helpers (`BlessedReplicaVersionRegistry` trait)

Access to the list of blessed (approved) replica versions.

#### Scenario: Get blessed replica versions
- **WHEN** `get_blessed_replica_versions(version)` is called
- **THEN** the `BlessedReplicaVersions` record is fetched from key `"blessed_replica_versions"`

#### Scenario: Get blessed guest launch measurements
- **WHEN** `get_blessed_guest_launch_measurements(version)` is called
- **THEN** the blessed replica versions are fetched
- **AND** for each blessed version, the `ReplicaVersionRecord` is retrieved
- **AND** all `guest_launch_measurements` from those records are collected and returned

### Requirement: Chain Keys Registry Helpers (`ChainKeysRegistry` trait)

Access to which subnets are enabled for each chain key.

#### Scenario: Get chain key enabled subnets
- **WHEN** `get_chain_key_enabled_subnets(version)` is called
- **THEN** all keys with prefix `"master_public_key_id_"` are enumerated
- **AND** for each key, the `ChainKeyEnabledSubnetList` is deserialized
- **AND** the result is a map from `MasterPublicKeyId` to `Vec<SubnetId>`
- **AND** keys with empty subnet lists are excluded

### Requirement: Provisional Whitelist Registry Helpers (`ProvisionalWhitelistRegistry` trait)

Access to the provisional whitelist controlling canister creation APIs.

#### Scenario: Get provisional whitelist
- **WHEN** `get_provisional_whitelist(version)` is called
- **THEN** the `ProvisionalWhitelist` is fetched from key `"provisional_whitelist"`
- **AND** the protobuf is converted to the native `ProvisionalWhitelist` enum

### Requirement: Unassigned Node Registry Helpers (`UnassignedNodeRegistry` trait)

Access to the configuration for unassigned nodes.

#### Scenario: Get unassigned nodes config
- **WHEN** `get_unassigned_nodes_config(version)` is called
- **THEN** the `UnassignedNodesConfigRecord` is fetched from key `"unassigned_nodes_config"`

---

## Crate: `ic-registry-keys` (`rs/registry/keys`)

Provides functions to construct and parse well-known registry key strings. Compilable to both WASM and native targets since registry mutations come from various NNS canisters.

### Requirement: Key Construction

Each `make_*_key` function produces a deterministic key string by combining a well-known prefix with an entity identifier.

#### Scenario: Subnet keys
- **WHEN** `make_subnet_record_key(subnet_id)` is called
- **THEN** the returned string is `"subnet_record_<principal_id>"`

#### Scenario: Node keys
- **WHEN** `make_node_record_key(node_id)` is called
- **THEN** the returned string is `"node_record_<principal_id>"`

#### Scenario: Crypto TLS cert key
- **WHEN** `make_crypto_tls_cert_key(node_id)` is called
- **THEN** the returned string is `"crypto_tls_cert_<principal_id>"`

#### Scenario: Crypto node key
- **WHEN** `make_crypto_node_key(node_id, key_purpose)` is called
- **THEN** the returned string is `"crypto_record_<principal_id>_<key_purpose_number>"`

#### Scenario: Threshold signing public key
- **WHEN** `make_crypto_threshold_signing_pubkey_key(subnet_id)` is called
- **THEN** the returned string is `"crypto_threshold_signing_public_key_<subnet_id>"`

#### Scenario: Singleton keys
- **WHEN** `make_subnet_list_record_key()` is called, **THEN** it returns `"subnet_list"`
- **WHEN** `make_routing_table_record_key()` is called, **THEN** it returns `"routing_table"`
- **WHEN** `make_provisional_whitelist_record_key()` is called, **THEN** it returns `"provisional_whitelist"`
- **WHEN** `make_blessed_replica_versions_key()` is called, **THEN** it returns `"blessed_replica_versions"`
- **WHEN** `make_unassigned_nodes_config_record_key()` is called, **THEN** it returns `"unassigned_nodes_config"`
- **WHEN** `make_canister_migrations_record_key()` is called, **THEN** it returns `"canister_migrations"`

#### Scenario: Replica and HostOS version keys
- **WHEN** `make_replica_version_key(version_id)` is called
- **THEN** the returned string is `"replica_version_<version_id>"`
- **WHEN** `make_hostos_version_key(version_id)` is called
- **THEN** the returned string is `"hostos_version_<version_id>"`

#### Scenario: Firewall rules key
- **WHEN** `make_firewall_rules_record_key(scope)` is called with a `FirewallRulesScope`
- **THEN** the returned string is `"firewall_rules_<scope_string>"`

#### Scenario: API boundary node key
- **WHEN** `make_api_boundary_node_record_key(node_id)` is called
- **THEN** the returned string is `"api_boundary_node_<principal_id>"`

#### Scenario: Node operator key
- **WHEN** `make_node_operator_record_key(principal_id)` is called
- **THEN** the returned string is `"node_operator_record_<principal_id>"`

#### Scenario: Data center key
- **WHEN** `make_data_center_record_key(dc_id)` is called
- **THEN** the returned string is `"data_center_record_<lowercase_dc_id>"`

#### Scenario: Chain key enabled subnet list key
- **WHEN** `make_chain_key_enabled_subnet_list_key(key_id)` is called
- **THEN** the returned string is `"master_public_key_id_<key_id>"`

#### Scenario: CUP contents key
- **WHEN** `make_catch_up_package_contents_key(subnet_id)` is called
- **THEN** the returned string is `"catch_up_package_contents_<subnet_id>"`

#### Scenario: Canister ranges key with hex encoding
- **WHEN** `make_canister_ranges_key(range_start)` is called
- **THEN** the returned string is `"canister_ranges_<hex_encoded_principal_bytes>"`
- **AND** the hex encoding preserves lexicographic ordering of the underlying u64 canister IDs
- **AND** the function panics if the `CanisterId` is not a valid routable canister ID

### Requirement: Key Prefix Constants

Well-known key prefixes are exported as public constants for use in key family queries.

#### Scenario: Prefix constants
- **WHEN** key prefix constants are used
- **THEN** `NODE_RECORD_KEY_PREFIX` equals `"node_record_"`
- **AND** `SUBNET_RECORD_KEY_PREFIX` equals `"subnet_record_"`
- **AND** `CRYPTO_RECORD_KEY_PREFIX` equals `"crypto_record_"`
- **AND** `CRYPTO_TLS_CERT_KEY_PREFIX` equals `"crypto_tls_cert_"`
- **AND** `CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX` equals `"crypto_threshold_signing_public_key_"`
- **AND** `CANISTER_RANGES_PREFIX` equals `"canister_ranges_"`
- **AND** `API_BOUNDARY_NODE_RECORD_KEY_PREFIX` equals `"api_boundary_node_"`
- **AND** `NODE_OPERATOR_RECORD_KEY_PREFIX` equals `"node_operator_record_"`
- **AND** `REPLICA_VERSION_KEY_PREFIX` equals `"replica_version_"`
- **AND** `HOSTOS_VERSION_KEY_PREFIX` equals `"hostos_version_"`
- **AND** `DATA_CENTER_KEY_PREFIX` equals `"data_center_record_"`
- **AND** `ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX` equals `"key_id_"`
- **AND** `CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX` equals `"master_public_key_id_"`
- **AND** `ROOT_SUBNET_ID_KEY` equals `"nns_subnet_id"`

### Requirement: Key Parsing

Functions to extract identifiers from key strings by stripping the known prefix.

#### Scenario: Parse crypto node key round-trip
- **WHEN** `make_crypto_node_key(node_id, key_purpose)` produces a key and `maybe_parse_crypto_node_key` is called on it
- **THEN** the original `(NodeId, KeyPurpose)` pair is recovered
- **AND** `None` is returned if the key does not start with `"crypto_record_"`

#### Scenario: Parse crypto TLS cert key round-trip
- **WHEN** `make_crypto_tls_cert_key(node_id)` produces a key and `maybe_parse_crypto_tls_cert_key` is called on it
- **THEN** the original `NodeId` is recovered
- **AND** `None` is returned if the key does not start with `"crypto_tls_cert_"`

#### Scenario: Parse threshold signing pubkey key round-trip
- **WHEN** `make_crypto_threshold_signing_pubkey_key(subnet_id)` produces a key and `maybe_parse_crypto_threshold_signing_pubkey_key` is called on it
- **THEN** the original `SubnetId` is recovered

#### Scenario: Parse node record node ID
- **WHEN** `get_node_record_node_id("node_record_<principal>")` is called
- **THEN** the `PrincipalId` is extracted and returned

#### Scenario: Parse API boundary node record node ID
- **WHEN** `get_api_boundary_node_record_node_id("api_boundary_node_<principal>")` is called
- **THEN** the `PrincipalId` is extracted and returned

#### Scenario: Parse node operator ID from record key
- **WHEN** `get_node_operator_id_from_record_key("node_operator_record_<principal>")` is called
- **THEN** the `PrincipalId` is extracted and returned

#### Scenario: Parse ECDSA key ID from signing subnet list key
- **WHEN** `get_ecdsa_key_id_from_signing_subnet_list_key("key_id_<curve>:<name>")` is called
- **THEN** the `EcdsaKeyId` is parsed from the suffix
- **AND** a `DecodeError` is returned if the prefix does not match or the key ID format is invalid

#### Scenario: Parse MasterPublicKeyId round-trip
- **WHEN** `make_chain_key_enabled_subnet_list_key(key_id)` produces a key and `get_master_public_key_id_from_signing_subnet_list_key` is called on it
- **THEN** the original `MasterPublicKeyId` is recovered for all ECDSA curves and Schnorr algorithms

#### Scenario: Check key type predicates
- **WHEN** `is_node_record_key(key)` is called
- **THEN** it returns `true` if and only if the key starts with `"node_record_"`
- **WHEN** `is_node_operator_record_key(key)` is called
- **THEN** it returns `true` if and only if the key starts with `"node_operator_record_"`
- **WHEN** `is_data_center_record_key(key)` is called
- **THEN** it returns `true` if and only if the key starts with `"data_center_record_"`

### Requirement: Firewall Rules Scope

The `FirewallRulesScope` enum classifies firewall rule targets and supports string round-tripping.

#### Scenario: FirewallRulesScope display and parse round-trip
- **WHEN** a `FirewallRulesScope` variant is formatted to a string and parsed back
- **THEN** the original variant is recovered
- **AND** `Global` formats as `"global"`
- **AND** `ReplicaNodes` formats as `"replica_nodes"`
- **AND** `ApiBoundaryNodes` formats as `"api_boundary_nodes"`
- **AND** `Subnet(id)` formats as `"subnet_<principal>"`
- **AND** `Node(id)` formats as `"node_<principal>"`

#### Scenario: Parse firewall scope from parenthesized form
- **WHEN** `FirewallRulesScope::from_str("subnet(<principal>)")` is called
- **THEN** `Subnet(SubnetId)` is returned
- **WHEN** `FirewallRulesScope::from_str("node(<principal>)")` is called
- **THEN** `Node(NodeId)` is returned

#### Scenario: Get firewall rules record principal ID
- **WHEN** `get_firewall_rules_record_principal_id("firewall_rules_node_<principal>")` is called
- **THEN** the `PrincipalId` is extracted
- **AND** `None` is returned for keys that are not node or subnet scoped

---

## Crate: `ic-registry-local-store` (`rs/registry/local_store`)

Provides a file-backed local store for persisting certified registry records as protobuf files. Implements `LocalStoreReader`, `LocalStoreWriter`, and `RegistryDataProvider`.

### Requirement: Local Store File Layout

Each registry version is stored as a single protobuf file using a hierarchical directory structure derived from the hexadecimal version number.

#### Scenario: File path for a version
- **WHEN** a changelog entry is stored for version `v`
- **THEN** it is written to a path derived from the 16-digit hex representation of `v`
- **AND** the path is split into directory segments: `<10-chars>/<2-chars>/<2-chars>/<4-chars>.pb`
- **AND** version 0 is never stored (panics if attempted)

#### Scenario: Store changelog entry requires predecessor
- **WHEN** `store(version, changelog_entry)` is called with `version > 1`
- **THEN** the file for `version - 1` must already exist
- **AND** an `io::Error(NotFound)` is returned if the predecessor does not exist

#### Scenario: Store at version 0 panics
- **WHEN** `store(ZERO_REGISTRY_VERSION, ...)` is called
- **THEN** the call panics with `"Version must be > 0."`

### Requirement: Changelog Read/Write

The local store persists and retrieves changelogs as sequences of `ChangelogEntry` (lists of `KeyMutation`).

#### Scenario: Store and retrieve changelog
- **WHEN** a sequence of changelog entries is stored for versions 1 through N
- **THEN** `get_changelog_since_version(v)` returns entries from version `v+1` through N
- **AND** the entries are returned in version order

#### Scenario: Clear local store
- **WHEN** `clear()` is called
- **THEN** all versioned directories are removed
- **AND** subsequent calls to `get_changelog_since_version(0)` return an empty list
- **AND** new entries can be stored starting from version 1

#### Scenario: Extend an existing store
- **WHEN** entries for versions 1..200 exist and new entries for 201..300 are stored
- **THEN** `get_changelog_since_version(0)` returns all 300 entries
- **AND** `get_changelog_since_version(150)` returns entries 151..300

### Requirement: RegistryDataProvider Implementation

`LocalStoreImpl` implements `RegistryDataProvider` to serve as a data source for `RegistryClientImpl`.

#### Scenario: get_updates_since converts changelog to registry records
- **WHEN** `get_updates_since(version)` is called on a `LocalStoreImpl`
- **THEN** the changelog since `version` is read from disk
- **AND** each `KeyMutation` is converted to a `RegistryRecord` with the appropriate version offset
- **AND** the resulting records are suitable for consumption by `RegistryClientImpl::poll_once`

### Requirement: Compact Delta Serialization

Utilities for converting between changelog and compact protobuf delta format.

#### Scenario: Compact delta round-trip
- **WHEN** `changelog_to_compact_delta(version, changelog)` is called
- **THEN** the changelog is serialized to a compact protobuf `Delta` message
- **AND** `compact_delta_to_changelog(bytes)` can recover the original `(version, changelog)`

#### Scenario: Mainnet delta can be read
- **WHEN** the hardcoded mainnet delta artifact is decoded via `compact_delta_to_changelog`
- **THEN** the changelog is successfully parsed with the expected number of entries

### Requirement: Efficient Bulk Creation

`LocalStoreImpl::from_changelog` creates a store from a full changelog, optimizing directory creation and syncing.

#### Scenario: Create from changelog
- **WHEN** `LocalStoreImpl::from_changelog(changelog, path)` is called
- **THEN** all changelog entries are written sequentially using simple file writes
- **AND** parent directories are synced for durability
- **AND** the resulting store is equivalent to storing each entry individually

---

## Crate: `ic-registry-local-registry` (`rs/registry/local_registry`)

Provides `LocalRegistry`, a file-backed registry client that synchronizes with the NNS registry canister. It wraps a `FakeRegistryClient` backed by a `LocalStoreImpl` for on-disk persistence.

### Requirement: Local Registry Initialization

#### Scenario: Create from existing local store
- **WHEN** `LocalRegistry::new(local_store_path, query_timeout)` is called with a path containing registry data
- **THEN** the in-memory cache is populated from the local store
- **AND** the root subnet URLs and threshold public key are extracted from the cached data
- **AND** a `RegistryCanister` is created targeting those URLs with the specified query timeout

#### Scenario: Create from empty local store fails
- **WHEN** `LocalRegistry::new` is called with a path that has no registry data (version 0)
- **THEN** a `LocalRegistryError::EmptyRegistry` is returned

### Requirement: Synchronization with NNS

#### Scenario: sync_with_nns fetches certified changes
- **WHEN** `sync_with_nns()` is called
- **THEN** certified changes since the latest cached version are fetched from the NNS registry canister
- **AND** the changes are sorted by version and persisted to the local store
- **AND** `sync_with_local_store()` is called to update the in-memory cache

#### Scenario: sync_with_nns updates root subnet info
- **WHEN** `sync_with_nns()` is called and the root subnet topology has changed (different URLs or public key)
- **THEN** the cached `RegistryCanister` is recreated with the new URLs
- **AND** the root subnet info version is updated monotonically (never decreases even with concurrent updates)

#### Scenario: sync_with_local_store without NNS
- **WHEN** `sync_with_local_store()` is called
- **THEN** the in-memory `FakeRegistryClient` is updated to reflect the current state of the on-disk local store
- **AND** no NNS network calls are made

### Requirement: RegistryClient Trait Delegation

#### Scenario: All RegistryClient methods delegate to FakeRegistryClient
- **WHEN** any `RegistryClient` trait method is called on `LocalRegistry`
- **THEN** the call is forwarded to the internal `FakeRegistryClient`
- **AND** the result reflects the state of the local store as of the last sync

---

## Crate: `ic-registry-routing-table` (`rs/registry/routing_table`)

Defines the `RoutingTable`, `CanisterIdRange`, `CanisterIdRanges`, and `CanisterMigrations` types that map canister ID ranges to subnet IDs.

### Requirement: CanisterIdRange

A `CanisterIdRange` represents a closed interval `[start, end]` of canister IDs.

#### Scenario: Contains check
- **WHEN** `canister_id_range.contains(canister_id)` is called
- **THEN** `true` is returned if `start <= canister_id <= end`

#### Scenario: Generate next canister ID with no previous
- **WHEN** `generate_canister_id(None)` is called on a range
- **THEN** `Some(start)` is returned

#### Scenario: Generate next canister ID within range
- **WHEN** `generate_canister_id(Some(prev))` is called and `start <= prev < end`
- **THEN** `Some(prev + 1)` is returned

#### Scenario: Generate canister ID at range end
- **WHEN** `generate_canister_id(Some(prev))` is called and `prev >= end`
- **THEN** `None` is returned

#### Scenario: Generate canister ID before range start
- **WHEN** `generate_canister_id(Some(prev))` is called and `prev < start`
- **THEN** `Some(start)` is returned

#### Scenario: Parse CanisterIdRange from string
- **WHEN** a string of the form `"<canister_id_1>:<canister_id_2>"` is parsed
- **THEN** a `CanisterIdRange { start, end }` is returned
- **AND** `CanisterIdRangeEmpty` is returned if `start > end`
- **AND** `CanisterIdsNotPair` is returned if the string does not contain exactly two colon-separated IDs

### Requirement: CanisterIdRanges

A validated, sorted, non-overlapping collection of canister ID ranges.

#### Scenario: Well-formedness validation
- **WHEN** `CanisterIdRanges` is constructed from a `Vec<CanisterIdRange>` via `TryFrom`
- **THEN** the ranges are sorted
- **AND** validation ensures no range is empty and no two ranges overlap
- **AND** a `WellFormedError::CanisterIdRangeEmptyRange` or `CanisterIdRangeNotSortedOrNotDisjoint` is returned if validation fails

#### Scenario: Total count
- **WHEN** `total_count()` is called
- **THEN** the sum of all individual range lengths is returned as `u128`

#### Scenario: Contains check across ranges
- **WHEN** `contains(canister_id)` is called
- **THEN** `true` is returned if any contained range includes the canister ID

#### Scenario: Generate canister ID across ranges
- **WHEN** `generate_canister_id(previous)` is called
- **THEN** it finds the first range that can produce a successor and returns it

### Requirement: RoutingTable

An ordered map from `CanisterIdRange` to `SubnetId`. Ranges are non-overlapping and the table is automatically optimized (adjacent ranges for the same subnet are merged).

#### Scenario: Insert a new range
- **WHEN** `insert(canister_id_range, subnet_id)` is called with a non-overlapping range
- **THEN** the range is added to the routing table and the table is optimized
- **AND** `WellFormedError::RoutingTableNotDisjoint` is returned if the range overlaps existing entries
- **AND** `WellFormedError::RoutingTableEmptyRange` is returned if `start > end`

#### Scenario: Lookup canister assignment
- **WHEN** `lookup_entry(canister_id)` is called
- **THEN** the `(CanisterIdRange, SubnetId)` containing that canister ID is returned using binary search
- **AND** `None` is returned if the canister ID is not assigned

#### Scenario: Assign single canister
- **WHEN** `assign_canister(canister_id, destination)` is called
- **THEN** the canister is assigned to the destination subnet
- **AND** existing range mappings are split if necessary

#### Scenario: Assign ranges
- **WHEN** `assign_ranges(ranges, destination)` is called
- **THEN** all provided ranges are assigned to the destination subnet
- **AND** existing overlapping ranges are split or removed as needed
- **AND** the table is optimized after assignment

#### Scenario: Remove subnet
- **WHEN** `remove_subnet(subnet_id)` is called
- **THEN** all ranges mapped to the specified subnet are removed

#### Scenario: Insert subnet helper
- **WHEN** `routing_table_insert_subnet(routing_table, subnet_id)` is called
- **THEN** a new range of `CANISTER_IDS_PER_SUBNET` (1 << 20, approximately 1M) canister IDs is allocated
- **AND** the range starts immediately after the last existing range

#### Scenario: Optimization merges adjacent same-subnet ranges
- **WHEN** `optimize()` is called or runs implicitly after modifications
- **THEN** adjacent ranges mapped to the same subnet are merged into a single range
- **AND** the `well_formed()` invariant holds: ranges are non-empty, sorted, disjoint, and optimized

### Requirement: CanisterMigrations

Tracks in-progress canister migrations between subnets with migration traces.

#### Scenario: Insert migration ranges
- **WHEN** `insert_ranges(ranges, source, destination)` is called
- **THEN** mappings from ranges to `[source, destination]` traces are added
- **AND** `CanisterMigrationsNotDisjoint` error is returned if ranges overlap existing migrations

#### Scenario: Remove migration ranges
- **WHEN** `remove_ranges(ranges, trace)` is called
- **THEN** all specified ranges are removed if their traces exactly match
- **AND** an error is returned if any range does not match the provided trace

#### Scenario: Migration well-formedness
- **WHEN** `well_formed()` is called
- **THEN** ranges must be non-empty, sorted, and disjoint
- **AND** each migration trace must have at least 2 subnets with no two successive subnets being the same

#### Scenario: Lookup canister migration
- **WHEN** `lookup(canister_id)` is called
- **THEN** the migration trace for the canister is returned, or `None` if not migrating

### Requirement: Set Operations on Ranges

Utility functions for comparing and combining canister ID range collections.

#### Scenario: Disjoint check
- **WHEN** `are_disjoint(left, right)` is called with two sorted range iterators
- **THEN** `true` is returned if and only if no range in `left` overlaps any range in `right`

#### Scenario: Subset check
- **WHEN** `is_subset_of(subset, superset)` is called
- **THEN** `true` is returned if every range in `subset` is fully contained by exactly one range in `superset`

#### Scenario: Intersection
- **WHEN** `intersection(lhs, rhs)` is called
- **THEN** the overlapping portions of ranges from both collections are returned as a new `CanisterIdRanges`

#### Scenario: Difference
- **WHEN** `difference(lhs, rhs)` is called
- **THEN** the portions of `lhs` ranges that do not overlap with `rhs` are returned

---

## Crate: `ic-registry-subnet-features` (`rs/registry/subnet_features`)

Defines `SubnetFeatures`, `KeyConfig`, and `ChainKeyConfig` for per-subnet feature flag and chain key signing configuration.

### Requirement: SubnetFeatures Flags

#### Scenario: Default subnet features
- **WHEN** `SubnetFeatures::default()` is called
- **THEN** `canister_sandboxing` is `false`
- **AND** `http_requests` is `true` (enabled by default)
- **AND** `sev_enabled` is `false`

#### Scenario: Parse from comma-separated string
- **WHEN** `SubnetFeatures::from_str("canister_sandboxing,sev_enabled")` is called
- **THEN** `canister_sandboxing` and `sev_enabled` are `true`
- **AND** `http_requests` defaults to `true`

#### Scenario: Parse "None" string
- **WHEN** `SubnetFeatures::from_str("None")` is called
- **THEN** the default `SubnetFeatures` is returned

#### Scenario: Parse unknown feature
- **WHEN** `SubnetFeatures::from_str("unknown_feature")` is called
- **THEN** an error is returned indicating the unknown feature

#### Scenario: Protobuf round-trip
- **WHEN** a `SubnetFeatures` is converted to `pb::SubnetFeatures` and back
- **THEN** the original value is recovered
- **AND** `sev_enabled` is stored as `Option<bool>` in protobuf (only `Some(true)` when enabled)

### Requirement: KeyConfig for Chain Key Signing

#### Scenario: KeyConfig fields
- **WHEN** a `KeyConfig` is created
- **THEN** it contains a `key_id` (`MasterPublicKeyId`), optional `pre_signatures_to_create_in_advance`, and a `max_queue_size`
- **AND** `DEFAULT_ECDSA_MAX_QUEUE_SIZE` is 20

#### Scenario: KeyConfig requires pre_signatures for pre-signature key types
- **WHEN** a `KeyConfig` is deserialized from protobuf with a key that requires pre-signatures
- **THEN** `pre_signatures_to_create_in_advance` must be present
- **AND** a `ProxyDecodeError::MissingField` is returned if it is absent

### Requirement: ChainKeyConfig

#### Scenario: ChainKeyConfig round-trip
- **WHEN** a `ChainKeyConfig` with ECDSA and VetKD key configs is converted to protobuf and back
- **THEN** the original config is recovered including `signature_request_timeout_ns`, `idkg_key_rotation_period_ms`, and `max_parallel_pre_signature_transcripts_in_creation`

#### Scenario: Get key IDs from ChainKeyConfig
- **WHEN** `key_ids()` is called on a `ChainKeyConfig`
- **THEN** the list of `MasterPublicKeyId` from all key configs is returned

#### Scenario: Get specific key config
- **WHEN** `key_config(key_id)` is called
- **THEN** the `KeyConfig` for the given key ID is returned, or `None` if not configured

---

## Crate: `ic-registry-subnet-type` (`rs/registry/subnet_type`)

Defines the `SubnetType` enum representing the different kinds of subnets on the Internet Computer.

### Requirement: SubnetType Variants and Conversions

#### Scenario: Application subnet (default)
- **WHEN** `SubnetType::default()` is called
- **THEN** `SubnetType::Application` is returned
- **AND** it serializes as `"application"` and converts to integer `1`

#### Scenario: System subnet
- **WHEN** `SubnetType::System` is used
- **THEN** it serializes as `"system"` and converts to integer `2`

#### Scenario: VerifiedApplication subnet
- **WHEN** `SubnetType::VerifiedApplication` is used
- **THEN** it serializes as `"verified_application"` and converts to integer `4`

#### Scenario: CloudEngine subnet
- **WHEN** `SubnetType::CloudEngine` is used
- **THEN** it serializes as `"cloud_engine"` and converts to integer `5`

#### Scenario: Parse from string
- **WHEN** `SubnetType::from_str("application")` is called
- **THEN** `SubnetType::Application` is returned
- **AND** all variants can be round-tripped through their `strum` string representations

#### Scenario: Invalid integer conversion
- **WHEN** `SubnetType::try_from(3_i32)` is called (or any unrecognized integer)
- **THEN** a `ProxyDecodeError::ValueOutOfRange` error is returned

#### Scenario: Protobuf round-trip
- **WHEN** a `SubnetType` is converted to `pb::SubnetType` and back
- **THEN** the original variant is recovered
- **AND** `pb::SubnetType::Unspecified` maps to a `ProxyDecodeError::ValueOutOfRange` error

---

## Crate: `ic-registry-nns-data-provider` (`rs/registry/nns_data_provider`)

Provides the `RegistryCanister` struct for querying the NNS registry canister, and certification verification logic for validating certified registry responses.

### Requirement: RegistryCanister Interaction

#### Scenario: Create with multiple URLs
- **WHEN** `RegistryCanister::new(urls)` is called with a non-empty list of URLs
- **THEN** an `Agent` is created for each URL using anonymous sender
- **AND** the canister ID defaults to the NNS registry canister ID
- **AND** requests are load-balanced by choosing a random agent

#### Scenario: Create with query timeout
- **WHEN** `RegistryCanister::new_with_query_timeout(urls, timeout)` is called
- **THEN** each agent is configured with the specified query timeout

#### Scenario: Create with empty URLs panics
- **WHEN** `RegistryCanister::new(vec![])` is called
- **THEN** the call panics with `"empty list of URLs passed to RegistryCanister::new()"`

#### Scenario: Get changes since a version
- **WHEN** `get_changes_since(version)` is called
- **THEN** a query for `"get_changes_since"` is sent to a random NNS replica
- **AND** the response is deserialized into `Vec<RegistryDelta>` and the latest version
- **AND** large values (high capacity) are dechunkified by calling `get_chunk` on the registry canister

#### Scenario: Get changes since as registry records
- **WHEN** `get_changes_since_as_registry_records(version)` is called
- **THEN** deltas are fetched and converted to `Vec<RegistryRecord>` sorted by version

#### Scenario: Get certified changes since a version
- **WHEN** `get_certified_changes_since(version, nns_public_key)` is called
- **THEN** the certified response is fetched and verified against the NNS threshold public key
- **AND** the returned records are guaranteed authentic and sorted by version

#### Scenario: Get latest version
- **WHEN** `get_latest_version()` is called
- **THEN** the `"get_latest_version"` query is sent to a random agent
- **AND** the response is decoded as a `RegistryGetLatestVersionResponse`

#### Scenario: Get value by key
- **WHEN** `get_value(key, version_opt)` is called
- **THEN** the `"get_value"` query is sent and the response is deserialized
- **AND** large values are dechunkified if needed

#### Scenario: Atomic mutate
- **WHEN** `atomic_mutate(mutations, preconditions)` is called
- **THEN** the mutations and preconditions are serialized and sent as an update call to `"atomic_mutate"`
- **AND** the new version is returned on success, or a list of errors on failure

### Requirement: Certification Verification

#### Scenario: Valid certified response
- **WHEN** a certified response is decoded and verified
- **THEN** the certificate signature is validated against the NNS public key
- **AND** the certified data hash matches the root hash of the mixed hash tree
- **AND** the delta entries are deserialized into `RegistryRecord` values

#### Scenario: Invalid signature
- **WHEN** a certified response has an invalid signature
- **THEN** a `CertificationError::InvalidSignature` is returned

#### Scenario: Certified data mismatch
- **WHEN** the certified data does not match the computed root hash
- **THEN** a `CertificationError::CertifiedDataMismatch` is returned

#### Scenario: Invalid deltas (non-contiguous versions)
- **WHEN** the decoded deltas have non-contiguous versions
- **THEN** a `CertificationError::InvalidDeltas` is returned

---

## Crate: `ic-registry-nns-data-provider-wrappers` (`rs/registry/nns_data_provider_wrappers`)

Provides wrapper types that adapt `RegistryCanister` into the `RegistryDataProvider` trait, bridging the async NNS queries to the synchronous `get_updates_since` interface.

### Requirement: NnsDataProvider (uncertified)

#### Scenario: Create and poll
- **WHEN** `NnsDataProvider::new(rt_handle, urls)` is created
- **THEN** it wraps a `RegistryCanister` targeting the given URLs
- **AND** `get_updates_since(version)` calls `get_changes_since_as_registry_records(version)` using `block_in_place`
- **AND** errors are mapped to `RegistryDataProviderError::Transfer`

### Requirement: CertifiedNnsDataProvider (certified)

#### Scenario: Create and poll with certification
- **WHEN** `CertifiedNnsDataProvider::new(rt_handle, urls, nns_public_key)` is created
- **THEN** it wraps a `RegistryCanister` and an NNS public key
- **AND** `get_updates_since(version)` calls `get_certified_changes_since(version, &nns_public_key)` using `block_in_place`
- **AND** all returned records have been cryptographically verified against the NNS public key

### Requirement: Factory Function

#### Scenario: create_nns_data_provider with public key
- **WHEN** `create_nns_data_provider(rt_handle, urls, Some(nns_pk))` is called
- **THEN** a `CertifiedNnsDataProvider` is returned (wrapped in `Arc<dyn RegistryDataProvider>`)

#### Scenario: create_nns_data_provider without public key
- **WHEN** `create_nns_data_provider(rt_handle, urls, None)` is called
- **THEN** an uncertified `NnsDataProvider` is returned

---

## Crate: `ic-registry-transport` (`rs/registry/transport`)

Provides protobuf type definitions and serialization/deserialization utilities for the registry canister wire protocol. Also defines the `Error` type for registry canister responses and mutation helper functions.

### Requirement: Registry Transport Error Types

#### Scenario: Error variants
- **WHEN** a registry canister returns an error
- **THEN** it is represented as one of: `MalformedMessage`, `KeyNotPresent`, `KeyAlreadyPresent`, `VersionNotLatest`, `VersionBeyondLatest`, `RegistryUnreachable`, or `UnknownError`

#### Scenario: Error conversion from RegistryError protobuf
- **WHEN** a `RegistryError` protobuf with error code is received
- **THEN** code 0 maps to `MalformedMessage`, code 1 to `KeyNotPresent`, code 2 to `KeyAlreadyPresent`, code 3 to `VersionNotLatest`
- **AND** unknown codes map to `UnknownError`

### Requirement: Request/Response Serialization

#### Scenario: get_value request round-trip
- **WHEN** `serialize_get_value_request(key, version_opt)` is called and then deserialized
- **THEN** the original key and version are recovered

#### Scenario: get_value response round-trip
- **WHEN** `serialize_get_value_response(response)` is called and then deserialized
- **THEN** the original response is recovered
- **AND** if the response contains an error, `deserialize_get_value_response` returns an `Err`

#### Scenario: get_changes_since request round-trip
- **WHEN** `serialize_get_changes_since_request(version)` is called and then deserialized
- **THEN** the original version is recovered

#### Scenario: get_changes_since response with error
- **WHEN** a `HighCapacityRegistryGetChangesSinceResponse` with an error field is deserialized
- **THEN** the error is converted to the transport `Error` type

#### Scenario: atomic_mutate request round-trip
- **WHEN** `serialize_atomic_mutate_request(mutations, preconditions)` is called and then deserialized
- **THEN** the original mutations and preconditions are recovered

#### Scenario: atomic_mutate response deserialization
- **WHEN** `deserialize_atomic_mutate_response(bytes)` is called
- **THEN** the new version is returned on success, or a `Vec<Error>` is returned if there are errors

### Requirement: Mutation Helper Functions

#### Scenario: Insert mutation
- **WHEN** `insert(key, value)` is called
- **THEN** a `RegistryMutation` with type `Insert` is created

#### Scenario: Update mutation
- **WHEN** `update(key, value)` is called
- **THEN** a `RegistryMutation` with type `Update` is created

#### Scenario: Delete mutation
- **WHEN** `delete(key)` is called
- **THEN** a `RegistryMutation` with type `Delete` and empty value is created

#### Scenario: Upsert mutation
- **WHEN** `upsert(key, value)` is called
- **THEN** a `RegistryMutation` with type `Upsert` is created

#### Scenario: Precondition helper
- **WHEN** `precondition(key, version)` is called
- **THEN** a `Precondition` with the specified key and expected version is created

### Requirement: Mutation Type Semantics

#### Scenario: Presence requirements
- **WHEN** mutation type `Insert` is used, **THEN** the key `MustBeAbsent`
- **WHEN** mutation type `Update` is used, **THEN** the key `MustBePresent`
- **WHEN** mutation type `Delete` is used, **THEN** the key `MustBePresent`
- **WHEN** mutation type `Upsert` is used, **THEN** there is `NoRequirement` on key presence

#### Scenario: Delete detection
- **WHEN** `Type::Delete.is_delete()` is called, **THEN** `true` is returned
- **WHEN** `Type::Insert.is_delete()` or `Type::Update.is_delete()` or `Type::Upsert.is_delete()` is called, **THEN** `false` is returned

### Requirement: High Capacity Protocol Compatibility

#### Scenario: Legacy and high-capacity request compatibility
- **WHEN** a legacy `RegistryAtomicMutateRequest` is encoded and decoded as `HighCapacityRegistryAtomicMutateRequest`
- **THEN** the conversion succeeds with equivalent data
- **AND** the reverse conversion (high-capacity to legacy) also succeeds

---

## Crate: `ic-registry-client-fake` (`rs/registry/fake`)

A fake implementation of `RegistryClient` intended for component tests and utility functions where a real registry with background polling is not required.

### Requirement: FakeRegistryClient Creation and Update

#### Scenario: Create with data provider
- **WHEN** `FakeRegistryClient::new(data_provider)` is called
- **THEN** the client is created with an empty cache at version zero
- **AND** no background thread is started

#### Scenario: Update to latest version
- **WHEN** `update_to_latest_version()` is called
- **THEN** `get_updates_since(latest_version)` is called on the data provider
- **AND** all new records are merged into the cache
- **AND** the latest version advances to the maximum version among new records
- **AND** the call panics if the data provider returns an error

#### Scenario: Reload
- **WHEN** `reload()` is called
- **THEN** the cache version is reset to `ZERO_REGISTRY_VERSION` and timestamps are cleared
- **AND** `update_to_latest_version()` is called to reload all data from the provider
- **AND** this is useful when test data was added at an already-existing version

### Requirement: RegistryClient Trait Implementation

#### Scenario: get_versioned_value behavior
- **WHEN** `get_versioned_value(key, version)` is called on `FakeRegistryClient`
- **THEN** it returns the most recent record for the key at or before the given version
- **AND** `VersionNotAvailable` error is returned if the version exceeds the latest cached version
- **AND** an empty record is returned for `ZERO_REGISTRY_VERSION`

#### Scenario: get_key_family behavior
- **WHEN** `get_key_family(prefix, version)` is called on `FakeRegistryClient`
- **THEN** all keys matching the prefix with non-None values at the given version are returned
- **AND** deleted keys are excluded

#### Scenario: get_latest_version
- **WHEN** `get_latest_version()` is called
- **THEN** the latest version in the cache is returned

#### Scenario: get_version_timestamp
- **WHEN** `get_version_timestamp(version)` is called
- **THEN** the timestamp recorded when the version was first added is returned

---

## Crate: `ic-registry-provisional-whitelist` (`rs/registry/provisional_whitelist`)

Defines the `ProvisionalWhitelist` enum controlling which principals can use provisional canister creation APIs.

### Requirement: Whitelist Variants

#### Scenario: All principals allowed
- **WHEN** `ProvisionalWhitelist::All` is used
- **THEN** `contains(id)` returns `true` for any `PrincipalId`

#### Scenario: Set-based whitelist
- **WHEN** `ProvisionalWhitelist::Set(set)` is used
- **THEN** `contains(id)` returns `true` only if `id` is in the set

#### Scenario: Empty whitelist
- **WHEN** `ProvisionalWhitelist::new_empty()` is called
- **THEN** a `Set` variant with an empty `BTreeSet` is returned
- **AND** `contains(id)` returns `false` for all principals

### Requirement: Protobuf Serialization

#### Scenario: Round-trip through protobuf
- **WHEN** a `ProvisionalWhitelist` is converted to `pb::ProvisionalWhitelist` and back
- **THEN** the original value is recovered
- **AND** the `All` variant uses `ListType::All` with an empty set in protobuf
- **AND** the `Set` variant uses `ListType::Set` with the principal IDs serialized

#### Scenario: Invalid ListType deserialization
- **WHEN** a protobuf with an unrecognized `list_type` is deserialized
- **THEN** a `ProxyDecodeError::ValueOutOfRange` error is returned

---

## Crate: `ic-regedit` (`rs/registry/regedit`)

A command-line tool and library for inspecting and editing the registry. Supports reading from local stores or remote NNS, generating snapshots, computing diffs, and applying updates.

### Requirement: Snapshot Command

#### Scenario: Generate snapshot from local store
- **WHEN** the `Snapshot` command is executed with a `LocalStore` source and a version spec
- **THEN** the changelog is read from the local store
- **AND** a snapshot of the registry at the specified version is computed
- **AND** the snapshot is normalized (protobuf values decoded to JSON) and projected

#### Scenario: Generate snapshot at latest version
- **WHEN** the version spec is `RelativeToLatest(0)`
- **THEN** the snapshot reflects the latest version available in the source

### Requirement: CanisterToProto Command

#### Scenario: Export registry delta as protobuf
- **WHEN** the `CanisterToProto` command is executed with a version range and output path
- **THEN** the changelog is read, filtered to the specified version range, and sorted
- **AND** the result is serialized as a compact protobuf delta file

### Requirement: ShowDiff Command

#### Scenario: Compute diff between base and modified snapshot
- **WHEN** the `ShowDiff` command is executed with a registry spec and a modified snapshot
- **THEN** the base snapshot is loaded from the registry spec
- **AND** the diff between the base and the modified (expanded) snapshot is computed
- **AND** the normalized diff is returned as JSON

### Requirement: ApplyUpdate Command

#### Scenario: Apply snapshot changes to local store
- **WHEN** the `ApplyUpdate` command is executed with a local store path and modified snapshot
- **THEN** the diff between the current state and the modified snapshot is computed
- **AND** a changelog entry is generated from the diff
- **AND** the entry is stored to the local store at the appropriate version
- **AND** if `amend` is true, the previous version is overwritten instead

### Requirement: Registry Loading Utility

#### Scenario: Load registry local store as JSON
- **WHEN** `load_registry_local_store(path)` is called
- **THEN** a full snapshot at the latest version is computed and returned as a `serde_json::Value`
