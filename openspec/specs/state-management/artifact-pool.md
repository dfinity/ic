# Artifact Pool Management

**Crates**: `ic-artifact-pool`

The artifact pool manages consensus, certification, DKG, IDKG, ingress, and canister HTTP artifacts using a combination of in-memory and persistent storage.

## Requirements

### Requirement: Pool Version Compatibility

The artifact pool ensures compatibility between the pool contents and the current replica version.

#### Scenario: Matching replica version
- **WHEN** the persistent pool directory contains a `replica_version` file matching the current version
- **THEN** the pool is used as-is
- **AND** existing artifacts are preserved

#### Scenario: Mismatching replica version
- **WHEN** the persistent pool directory's `replica_version` does not match the current version
- **THEN** all contents of the pool directory are deleted
- **AND** a new pool directory is created
- **AND** the current replica version is written to the `replica_version` file

#### Scenario: Missing replica version file
- **WHEN** no `replica_version` file exists in the pool directory
- **THEN** the pool directory is treated as incompatible
- **AND** it is cleared and re-initialized with the current version

### Requirement: Consensus Pool

The consensus pool stores consensus artifacts (blocks, block proposals, notarizations, finalizations, random beacons, random tapes, catch-up packages, and equivocation proofs).

#### Scenario: Pool section operations
- **WHEN** mutations are applied to the consensus pool
- **THEN** the following operations are supported:
  - `Insert` - add an artifact to a pool section
  - `Remove` - remove an artifact by its `ConsensusMessageId`
  - `PurgeBelow(height)` - remove all artifacts strictly below a height
  - `PurgeTypeBelow(type, height)` - remove artifacts of a specific type below a height

#### Scenario: Validated and unvalidated sections
- **WHEN** consensus artifacts are stored
- **THEN** they are placed in either the validated or unvalidated section
- **AND** the validated section is backed by persistent storage (LMDB or RocksDB)
- **AND** the unvalidated section is in-memory only

#### Scenario: Height-indexed access
- **WHEN** artifacts are queried by height
- **THEN** the pool supports `HeightIndexedPool` interface
- **AND** artifacts can be retrieved by exact height or height range
- **AND** minimum and maximum heights are tracked per artifact type

#### Scenario: Consensus pool cache
- **WHEN** the consensus pool cache is maintained
- **THEN** it tracks the latest finalized block, the block chain, and the summary block
- **AND** the cache is updated on each pool mutation
- **AND** it provides efficient access to the consensus state without scanning the pool

#### Scenario: Consensus time
- **WHEN** consensus time is queried
- **THEN** the pool returns the timestamp of the latest finalized block
- **AND** this provides an approximation of current consensus time

### Requirement: Certification Pool

The certification pool stores certification artifacts (full certifications and certification shares).

#### Scenario: Certification pool operations
- **WHEN** mutations are applied to the certification pool
- **THEN** the following actions are supported:
  - `AddToValidated` - add a validated certification or share
  - `MoveToValidated` - promote an unvalidated artifact to validated
  - `RemoveAllFromUnvalidated` - clear all unvalidated artifacts
  - `RemoveFromUnvalidated` - remove a specific unvalidated artifact
  - `PurgeValidatedBelow(height)` - remove validated artifacts below a height
  - `PurgeUnvalidatedBelow(height)` - remove unvalidated artifacts below a height

#### Scenario: Share deduplication
- **WHEN** a certification share is added to the validated pool
- **THEN** it is stored only if no share from the same signer at the same height already exists

#### Scenario: Height range tracking
- **WHEN** certifications or shares are in the pool
- **THEN** their height range (min, max) is tracked via metrics
- **AND** pool size metrics are reported separately for certifications and shares

### Requirement: Ingress Pool

The ingress pool manages incoming user messages before they are included in blocks.

#### Scenario: Peer counter tracking
- **WHEN** ingress messages are received
- **THEN** the number of messages per peer (node ID) is tracked
- **AND** this enables per-peer rate limiting

### Requirement: DKG Pool

The DKG pool manages Distributed Key Generation protocol artifacts.

#### Scenario: DKG artifact storage
- **WHEN** DKG dealings are received
- **THEN** they are stored in either validated or unvalidated sections
- **AND** artifacts are indexed by height for efficient purging

### Requirement: IDKG Pool

The IDKG pool manages Internet Computer DKG (threshold ECDSA/Schnorr) artifacts.

#### Scenario: IDKG artifact storage
- **WHEN** IDKG artifacts are received (dealings, dealing support, signatures, complaints, openings)
- **THEN** they are stored with appropriate validation status
- **AND** artifacts are tracked by height

### Requirement: Canister HTTP Pool

The canister HTTP pool manages responses from canister HTTP outcalls.

#### Scenario: HTTP response storage
- **WHEN** canister HTTP responses are received
- **THEN** they are stored pending consensus inclusion
- **AND** responses are validated and matched to their originating requests

### Requirement: Persistent Storage Backends

The artifact pool supports multiple persistent storage backends.

#### Scenario: LMDB backend
- **WHEN** the LMDB backend is configured
- **THEN** validated consensus artifacts are stored in LMDB databases
- **AND** LMDB provides crash-consistent persistence
- **AND** iteration is supported via the `LmdbIterator`

#### Scenario: RocksDB backend (macOS only)
- **WHEN** the RocksDB backend is configured (available on macOS)
- **THEN** validated consensus artifacts are stored in RocksDB
- **AND** this avoids LMDB-related issues historically observed on macOS

#### Scenario: In-memory pool
- **WHEN** the in-memory backend is used
- **THEN** artifacts are stored only in memory
- **AND** this is used for unvalidated sections and testing

### Requirement: Pool Backup

The artifact pool supports backup of consensus artifacts.

#### Scenario: Backup creation
- **WHEN** backup is enabled
- **THEN** finalized blocks and their payloads are written to a backup directory
- **AND** backups are organized by height

### Requirement: Pool Metrics

The artifact pool reports comprehensive metrics.

#### Scenario: Pool size metrics
- **WHEN** pool metrics are queried
- **THEN** the following are reported per artifact type:
  - Maximum and minimum heights
  - Count of artifacts
  - Count per height (histogram)
- **AND** metrics are separated by pool type (validated vs. unvalidated)
