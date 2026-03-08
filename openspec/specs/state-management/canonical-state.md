# Canonical State

**Crates**: `ic-canonical-state`, `ic-canonical-state-tree-hash`, `tree-deserializer`

The Canonical State provides a deterministic, versioned representation of the public parts of a subnet's replicated state, used for inter-replica agreement via threshold signature certification.

## Requirements

### Requirement: Canonical State Structure

The canonical state is a labeled tree representing the externally visible parts of the replicated state.

#### Scenario: Top-level tree structure
- **WHEN** the canonical state tree is traversed
- **THEN** it contains the following top-level subtrees:
  - `canister` - per-canister public information
  - `request_status` - ingress message statuses
  - `streams` - cross-subnet communication streams
  - `subnet` - subnet-level metadata
  - `time` - current batch time

#### Scenario: Canister subtree structure
- **WHEN** a canister's subtree is traversed
- **THEN** it contains:
  - `certified_data` - the canister's certified data blob
  - `controllers` - encoded set of controllers
  - `metadata` - public custom sections from Wasm metadata
  - `module_hash` - SHA-256 hash of the Wasm module

#### Scenario: Stream subtree structure
- **WHEN** a stream subtree is traversed for a given subnet
- **THEN** it contains:
  - `header` - encoded stream header (begin, end, signals_end, etc.)
  - `messages` - individual stream messages keyed by index

#### Scenario: Subnet subtree structure
- **WHEN** the subnet subtree is traversed
- **THEN** it contains per-subnet information including:
  - `public_key` - the subnet's threshold public key
  - `canister_ranges` - canister ID ranges assigned to the subnet
  - `metrics` - subnet-level metrics
  - `node` - per-node information

### Requirement: Canonical Encoding

Leaf nodes in the canonical state tree are encoded using packed CBOR for deterministic binary representation.

#### Scenario: Stream message encoding
- **WHEN** a stream message is encoded canonically
- **THEN** it uses packed CBOR format where field names are replaced by indices
- **AND** the encoding is deterministic across all replicas using the same certification version

#### Scenario: Stream header encoding
- **WHEN** a stream header is encoded canonically
- **THEN** it includes begin, end, signals_end, and reject signals
- **AND** the encoding format depends on the certification version

#### Scenario: System metadata encoding
- **WHEN** system metadata is encoded canonically
- **THEN** it includes the certification version-appropriate fields

#### Scenario: Canister ranges encoding
- **WHEN** subnet canister ranges are encoded
- **THEN** they use self-describing CBOR encoding
- **AND** the format follows the IC interface specification

### Requirement: Certification Versioning

Canonical state encoding evolves through numbered certification versions with strict compatibility guarantees.

#### Scenario: Current certification version
- **WHEN** the replica starts
- **THEN** it uses `CURRENT_CERTIFICATION_VERSION` as its default encoding version
- **AND** it supports encoding for versions up to `CURRENT_CERTIFICATION_VERSION + 1`

#### Scenario: Unsupported version panic
- **WHEN** a replica is asked to encode canonical state using a version greater than `CURRENT_CERTIFICATION_VERSION + 1`
- **THEN** it panics to prevent undefined behavior

#### Scenario: Backward compatible changes
- **WHEN** a new field is added to the canonical encoding
- **THEN** it is introduced as optional and unpopulated in certification version N+1
- **AND** it is populated starting from certification version N+2
- **AND** this ensures downgrade from N+2 to N+1 works because N+1 can encode N+2 format

#### Scenario: Forward compatible removal
- **WHEN** a field is removed from the canonical encoding
- **THEN** it is first made optional (if not already) in one version
- **AND** actual removal happens in a subsequent version after deployment

#### Scenario: Two-phase version rollout
- **WHEN** canonical encoding changes are deployed
- **THEN** they span two certification versions:
  - Version N+1: same encoding as N, but supports producing N+2 encoding
  - Version N+2: uses the new encoding
- **AND** subnet upgrades must happen between each phase

### Requirement: Lazy Tree Conversion

The replicated state is converted to a lazy tree representation for efficient traversal and hashing.

#### Scenario: Lazy tree from replicated state
- **WHEN** `replicated_state_as_lazy_tree` is called
- **THEN** a `LazyTree` is constructed that lazily evaluates subtrees on demand
- **AND** leaf encoding is deferred until the leaf is actually accessed
- **AND** the tree structure matches the canonical state specification

#### Scenario: Finite map construction
- **WHEN** a `FiniteMap` is built for a lazy tree node
- **THEN** each child can be either an eagerly computed value or a lazy function
- **AND** children can be conditionally included based on certification version

#### Scenario: Maximum routing table ranges per leaf
- **WHEN** routing table ranges are included in a canonical state leaf
- **THEN** at most `MAX_RANGES_PER_ROUTING_TABLE_LEAF` (5) disjoint ranges are included per leaf
- **AND** changes to this constant require a new certification version

### Requirement: Tree Traversal

The canonical state tree is traversed using the Visitor pattern to support multiple use cases.

#### Scenario: Visitor-based traversal
- **WHEN** `traverse(state, height, visitor)` is called
- **THEN** the visitor receives callbacks in order:
  - `start_subtree` - entering a fork node
  - `enter_edge(label)` - descending along a labeled edge
  - `visit_blob(data)` / `visit_num(n)` - visiting leaf nodes
  - `end_subtree` - leaving a fork node
  - `finish` - traversal complete

#### Scenario: Skipping subtrees
- **WHEN** a visitor returns `Control::Skip` from `enter_edge`
- **THEN** the entire subtree below that edge is skipped
- **AND** no `start_subtree`, `visit_*`, or `end_subtree` calls are made for it

#### Scenario: Early termination
- **WHEN** a visitor returns `Err(output)` from any callback
- **THEN** the traversal terminates immediately
- **AND** the error value is returned as the traversal result

### Requirement: Subtree Visitor

The `SubtreeVisitor` filters the tree traversal to only visit specific subtrees.

#### Scenario: Pattern matching traversal
- **WHEN** a `SubtreeVisitor` is configured with a pattern
- **THEN** only edges matching the pattern are traversed
- **AND** non-matching edges are automatically skipped

#### Scenario: Wildcard matching
- **WHEN** a pattern includes `Pattern::any(sub_pattern)`
- **THEN** all edges at that level are matched
- **AND** each matched edge's children are filtered by `sub_pattern`

### Requirement: Size Limit Visitor

The `SizeLimitVisitor` limits the total size of data visited.

#### Scenario: Enforcing byte limits on stream encoding
- **WHEN** a `SizeLimitVisitor` is used to encode stream messages
- **THEN** messages are included until the byte limit is reached
- **AND** the actual end index is returned alongside the encoded tree

### Requirement: Canonical State Proxy Types

Mirror types in the encoding module provide stable CBOR serialization.

#### Scenario: Proxy encoding roundtrip
- **WHEN** a Rust type is encoded via its canonical proxy type
- **THEN** the packed CBOR output is deterministic
- **AND** decoding via the proxy type recovers the original value

#### Scenario: Compatibility tests
- **WHEN** the canonical encoding types are tested
- **THEN** field indices in packed CBOR match expected values
- **AND** adding/removing fields is detected by compatibility tests
- **AND** changes to encoding types require explicit test updates
