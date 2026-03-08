# Consensus Types

## Requirements

### Requirement: Block Chain Structure
A Block represents a unit in the blockchain, containing a version, parent hash, payload, height, rank, and validation context. Blocks form a hash-linked chain where each block references its parent.

#### Scenario: Block construction
- **WHEN** Block::new(parent, payload, height, rank, context) is called
- **THEN** the block has version set to ReplicaVersion::default()
- **AND** the parent field references the parent block's CryptoHashOf<Block>

#### Scenario: Block height invariant
- **WHEN** a block is created
- **THEN** its height MUST be parent.height + 1

#### Scenario: Block rank ordering
- **WHEN** multiple block proposals exist at the same height
- **THEN** rank 0 indicates the highest priority block maker
- **AND** higher rank values indicate lower priority

### Requirement: HashedBlock Content-Addressable Block
HashedBlock pairs a Block with its CryptoHashOf<Block>, providing content-addressable access to blocks in the pool.

#### Scenario: HashedBlock log entry
- **WHEN** log_entry() is called on a HashedBlock
- **THEN** a BlockLogEntry is produced containing certified_height, hash, height, parent_hash, rank, registry_version, time, and version

### Requirement: BlockMetadata Signable Block Summary
BlockMetadata captures version, height, subnet_id, and hash of a block for signing purposes, serialized via CBOR.

#### Scenario: BlockMetadata signing bytes
- **WHEN** as_signed_bytes_without_domain_separator() is called
- **THEN** the result is the CBOR serialization of the BlockMetadata

### Requirement: Rank Block Maker Priority
Rank(u64) indicates the priority of a block maker, where Rank(0) is the highest priority.

#### Scenario: Rank comparison
- **WHEN** ranks are compared
- **THEN** lower numeric values indicate higher priority
- **AND** Rank implements Ord for total ordering

### Requirement: ValidationContext Consensus Prerequisites
ValidationContext captures the registry_version, certified_height, and time required for validating a payload.

#### Scenario: ValidationContext monotonicity check
- **WHEN** greater_or_equal(&other) is called
- **THEN** it returns true only if ALL three fields (registry_version, certified_height, time) are >= those of other
- **AND** this is NOT a lexicographic comparison

#### Scenario: ValidationContext strict time check
- **WHEN** greater(&other) is called
- **THEN** it returns true only if registry_version >= other, certified_height >= other, AND time > other (strictly greater)

### Requirement: Consensus Abstract Trait Hierarchy
Consensus messages implement a hierarchy of traits: HasHeight, HasRank, HasVersion, HasBlockHash, HasCommittee, HasHash, and IsShare.

#### Scenario: HasHeight propagation through Signed
- **WHEN** HasHeight is implemented on content type T
- **THEN** Signed<T, S> also implements HasHeight, delegating to content.height()

#### Scenario: HasVersion propagation through Hashed
- **WHEN** HasVersion is implemented on value type T
- **THEN** Hashed<H, T> also implements HasVersion, delegating to value.version()

#### Scenario: Committee assignment
- **WHEN** HasCommittee is implemented for NotarizationContent
- **THEN** committee() returns Committee::Notarization
- **WHEN** HasCommittee is implemented for RandomBeaconContent
- **THEN** committee() returns Committee::LowThreshold

### Requirement: NotarizationContent Block Attestation
NotarizationContent records that a committee of nodes has attested to a block at a specific height.

#### Scenario: NotarizationContent fields
- **WHEN** a NotarizationContent is created
- **THEN** it contains a version, height, and block hash (CryptoHashOf<Block>)

### Requirement: FinalizationContent Block Finality
FinalizationContent marks a block as finalized, sharing the same structure as NotarizationContent but using the Notarization committee.

#### Scenario: FinalizationContent committee
- **WHEN** FinalizationContent::committee() is called
- **THEN** it returns Committee::Notarization (same committee handles both)

### Requirement: RandomBeaconContent Distributed Randomness
RandomBeaconContent provides verifiable randomness at each height using low threshold signatures.

#### Scenario: RandomBeaconContent chain linking
- **WHEN** a RandomBeaconContent is created at height h
- **THEN** it references the CryptoHashOf<RandomBeacon> at height h-1
- **AND** uses Committee::LowThreshold for signing

### Requirement: RandomTapeContent Execution Randomness
RandomTapeContent provides randomness for execution at a specific height.

#### Scenario: RandomTapeContent committee
- **WHEN** RandomTapeContent is created
- **THEN** it uses Committee::LowThreshold

### Requirement: EquivocationProof Misbehavior Detection
EquivocationProof provides evidence that a node has created conflicting blocks at the same height.

#### Scenario: EquivocationProof identification
- **WHEN** an EquivocationProof is constructed
- **THEN** it contains the version, height, and evidence of the conflicting proposals

### Requirement: Batch Consensus-to-Execution Handoff
Batch is the primary data structure passed from Consensus to Message Routing for deterministic processing.

#### Scenario: Batch data content
- **WHEN** a Batch with BatchContent::Data is delivered
- **THEN** it contains batch_messages, consensus_responses, chain_key_data, and requires_full_state_hash flag
- **AND** batch_number (Height), randomness, registry_version, time, blockmaker_metrics, and replica_version

#### Scenario: Batch splitting content
- **WHEN** a Batch with BatchContent::Splitting is delivered
- **THEN** it contains new_subnet_id and other_subnet_id
- **AND** requires_full_state_hash is always true for splitting rounds

#### Scenario: Batch checkpoint determination
- **WHEN** requires_full_state_hash() is called on a Data batch
- **THEN** it returns the explicit requires_full_state_hash flag
- **WHEN** called on a Splitting batch
- **THEN** it always returns true

### Requirement: BatchPayload Component Payloads
BatchPayload aggregates IngressPayload, XNetPayload, SelfValidatingPayload, CanisterHttpPayload, QueryStatsPayload, and VetKdPayload.

#### Scenario: IngressPayload size constraint
- **WHEN** IngressPayload is built by the IngressSelector
- **THEN** count_bytes() MUST NOT exceed the provided byte_limit

### Requirement: ConsensusMessage Artifact Identification
ConsensusMessage is the envelope for all consensus artifacts with a unique ConsensusMessageId (hash + height).

#### Scenario: ConsensusMessageId construction
- **WHEN** ConsensusMessageId is created from a ConsensusMessage
- **THEN** the hash field contains the ConsensusMessageHash
- **AND** the height field matches the message's height

### Requirement: Payload Summary vs Data Distinction
Payload can be either a SummaryPayload (at DKG interval boundaries) or a DataPayload (containing batch messages).

#### Scenario: Payload type check
- **WHEN** payload.is_summary() is called
- **THEN** it returns true for summary payloads at DKG interval boundaries
- **AND** false for data payloads
