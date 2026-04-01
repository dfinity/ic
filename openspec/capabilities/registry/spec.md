# Registry Capability Specification

**Source narrative**: `openspec/specs/registry/spec.md`
**Crates**: `registry-canister`, `ic-registry-canister-client`, `ic-registry-replicator`
**Key files**: `rs/registry/canister/`, `rs/registry/replicator/`

---

## REQ-REG-001: Versioned Key-Value Store

The registry MUST store key-value pairs where each mutation atomically increments a global version.

### SCENARIO-REG-001: Insert requires key absence
**Given** an insert mutation is applied for a key
**When** the mutation runs
**Then** the key must not already exist
**And** an error is returned if the key is already present

### SCENARIO-REG-002: Update requires key presence
**Given** an update mutation is applied for a key
**When** the mutation runs
**Then** the key must already exist
**And** an error is returned if the key is absent

### SCENARIO-REG-003: Upsert has no presence requirement
**Given** an upsert mutation is applied for a key
**When** the mutation runs
**Then** the mutation succeeds regardless of whether the key exists

### SCENARIO-REG-004: Atomic mutate applies all or none
**Given** an atomic mutate request contains multiple mutations
**When** a precondition fails on any mutation
**Then** none of the mutations are applied
**And** the registry version is not incremented

### SCENARIO-REG-005: Version increments on each mutation batch
**Given** a batch of mutations is successfully applied
**When** the batch is applied
**Then** the registry version increments by exactly one
**And** changelog versions form a contiguous sequence starting from 1

---

## REQ-REG-002: Registry Certification

Registry updates MUST be certified using hash trees for client verification.

### SCENARIO-REG-006: Hash tree structure for certification
**Given** the registry state is certified
**When** the hash tree is constructed
**Then** it contains `current_version` (LEB128-encoded) at the root
**And** a `delta` subtree mapping big-endian version numbers to serialized changelog entries

### SCENARIO-REG-007: Certified data updated on each mutation
**Given** a mutation is applied
**When** certified data is updated
**Then** the canister's certified data is recalculated from the root hash

### SCENARIO-REG-008: Clients verify certified responses
**Given** a client receives a certified registry response
**When** verification runs
**Then** the threshold signature is verified against the NNS subnet public key
**And** the certified data matches the hash tree reconstruction
**And** the canister ID is within the delegation's allowed range

---

## REQ-REG-003: Invariant Checks

Before any mutation is applied, the registry MUST validate that global invariants hold.

### SCENARIO-REG-009: Invariant checks prevent invalid mutations
**Given** mutations are submitted via `maybe_apply_mutation_internal`
**When** invariant checks run
**Then** global state invariants are checked against the prospective new state
**And** the mutation is rejected if any invariant is violated

### SCENARIO-REG-010: Routing table invariant
**Given** the registry state is validated
**When** the routing table check runs
**Then** the routing table must be well-formed with non-overlapping canister ID ranges

### SCENARIO-REG-011: Node chip ID uniqueness
**Given** a node record with a chip_id is being registered
**When** the uniqueness check runs
**Then** each node's chip_id (if non-empty) must be unique across all nodes

### SCENARIO-REG-012: Free cycles schedule restriction
**Given** a subnet's cycles cost schedule is set to "Free"
**When** the invariant check runs
**Then** the subnet type must be Application or CloudEngine
**And** System subnets are not allowed to have a free cycles schedule

---

## REQ-REG-004: Subnet Management

The registry MUST support creating, recovering, and updating subnets through governance proposals.

### SCENARIO-REG-013: Successful subnet creation
**Given** a `CreateSubnetPayload` is submitted with valid node IDs
**When** creation runs
**Then** NI-DKG is performed via `setup_initial_dkg`, a subnet record is inserted, a CUP is created with DKG transcripts, a threshold signing key is stored, and the routing table is updated

### SCENARIO-REG-014: All nodes must exist in registry
**Given** a subnet creation payload references a non-existent node
**When** validation runs
**Then** the operation panics with "A NodeRecord for Node with id ... was not found"

### SCENARIO-REG-015: Nodes must not belong to another subnet
**Given** a subnet creation payload includes nodes already assigned to a subnet
**When** validation runs
**Then** the operation panics with "Some Nodes are already members of Subnets"

### SCENARIO-REG-016: Subnet recovery updates DKG and CUP
**Given** a `RecoverSubnetPayload` is submitted for a stalled subnet
**When** recovery runs
**Then** a new DKG is performed, the CUP contents are updated with new transcripts, and the height/time/state hash are set from the payload

### SCENARIO-REG-017: Subnet update merges specified fields
**Given** an `UpdateSubnetPayload` is submitted
**When** the update runs
**Then** the specified fields are merged into the existing subnet record with invariants checked

---

## REQ-REG-005: Node Management

The registry MUST support adding, removing, and reassigning nodes.

### SCENARIO-REG-018: Successful node addition
**Given** a valid `AddNodePayload` is submitted by a node operator with allowance
**When** addition runs
**Then** the node record is created with network endpoints and all 5 cryptographic keys, and the operator's allowance is decremented

### SCENARIO-REG-019: Node operator must have allowance
**Given** a node operator with zero allowance tries to add a node
**When** validation runs
**Then** the operation is rejected

### SCENARIO-REG-020: IP address uniqueness
**Given** a node is added with an IP address already in use
**When** validation runs
**Then** the operation is rejected to prevent IP conflicts

### SCENARIO-REG-021: Node removal increments operator allowance
**Given** a `RemoveNodesPayload` is submitted for existing nodes
**When** removal runs
**Then** node records and all associated crypto key records are deleted
**And** the node operator's allowance is incremented by the number of removed nodes
**And** nodes that are subnet members cannot be removed

---

## REQ-REG-006: Replica Version Management

The registry MUST maintain a list of blessed replica versions.

### SCENARIO-REG-022: Elect a new replica version
**Given** a `ReviseElectedGuestosVersionsPayload` elects a new version
**When** election runs
**Then** a new `ReplicaVersionRecord` is inserted with release package URLs and SHA256 hash
**And** the version ID is added to the blessed replica versions list

### SCENARIO-REG-023: Cannot retire version deployed to subnet
**Given** a version to be retired is currently used by any subnet
**When** retirement runs
**Then** the operation panics with "Cannot retire versions ... because they are currently deployed to a subnet"

### SCENARIO-REG-024: Cannot elect and unelect same version
**Given** the same version appears in both elect and unelect lists
**When** validation runs
**Then** the operation panics with "cannot elect and unelect the same version"

---

## REQ-REG-007: Routing Table Management

The registry MUST manage the canister ID range to subnet mapping.

### SCENARIO-REG-025: New subnet gets routing table allocation
**Given** a new subnet is created
**When** the routing table is updated
**Then** a canister ID range (~1M IDs) is assigned to the new subnet

### SCENARIO-REG-026: Reroute canister ranges
**Given** a `RerouteCanisterRangesPayload` is submitted
**When** rerouting runs
**Then** the specified canister ID ranges are moved from source to destination subnet
**And** the rerouting must be covered by an existing canister migration entry

---

## REQ-REG-008: Canister Migration

The registry MUST support multi-step canister migration (prepare → reroute → complete).

### SCENARIO-REG-027: Prepare canister migration
**Given** a `PrepareCanisterMigrationPayload` is submitted
**When** preparation runs
**Then** the canister ID ranges are added to `canister_migrations`
**And** both subnets must be Application/VerifiedApplication type, same size, and same type
**And** neither subnet can hold chain keys, all canisters must be on source, none already migrating

### SCENARIO-REG-028: Complete canister migration
**Given** a `CompleteCanisterMigrationPayload` is submitted
**When** completion runs
**Then** the specified canister ID ranges are removed from canister_migrations
**And** the migration trace must match

---

## REQ-REG-009: Registry Client (Local Cache)

The registry client MUST maintain a local cache of registry data.

### SCENARIO-REG-029: Version-aware value lookup
**Given** `get_versioned_value(key, version)` is called
**When** the lookup runs
**Then** the most recent value at or before the requested version is returned
**And** if no value exists, an empty record is returned
**And** if version is beyond latest known, an error is returned

### SCENARIO-REG-030: Background polling
**Given** `fetch_and_start_polling()` is called
**When** polling starts
**Then** an initial synchronous poll is performed
**And** a background thread polls at `POLLING_PERIOD`
**And** the thread is stopped when the client is dropped

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-REG-001 | Versioned K-V store | linked | rs/registry/canister/tests/integration_tests_3.rs |
| REQ-REG-002 | Certification | linked | rs/registry/canister/tests/integration_tests_3.rs |
| REQ-REG-003 | Invariant checks | linked | rs/registry/canister/tests/integration_tests_3.rs |
| REQ-REG-004 | Subnet management | narrative | rs/registry/canister/tests/ |
| REQ-REG-005 | Node management | narrative | rs/registry/canister/tests/ |
| REQ-REG-006 | Replica version mgmt | narrative | rs/registry/canister/tests/ |
| REQ-REG-007 | Routing table | narrative | rs/registry/canister/tests/ |
| REQ-REG-008 | Canister migration | narrative | rs/registry/canister/tests/ |
| REQ-REG-009 | Registry client cache | narrative | rs/registry/canister/tests/ |
