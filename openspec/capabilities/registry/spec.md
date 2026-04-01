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

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-REG-001 | Versioned K-V store | narrative | rs/registry/canister/tests/ |
| REQ-REG-002 | Certification | narrative | rs/registry/canister/tests/ |
| REQ-REG-003 | Invariant checks | narrative | rs/registry/canister/tests/ |
