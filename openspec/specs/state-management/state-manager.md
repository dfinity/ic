# State Manager

**Crates**: `ic-state-manager`, `ic-state-sync-manager`

The State Manager is the central orchestrator for managing the replicated state of an Internet Computer subnet. It coordinates checkpointing, state certification, state synchronization, manifest computation, and state lifecycle management.

## Requirements

### Requirement: State Initialization

The State Manager must initialize correctly from persisted checkpoints on disk, recovering metadata and constructing the initial state.

#### Scenario: Fresh initialization with no checkpoints
- **WHEN** the State Manager is created with no existing checkpoints on disk
- **THEN** it initializes with a default state at height 0
- **AND** the tip is set to the initial state

#### Scenario: Initialization with existing checkpoints
- **WHEN** the State Manager is created with existing verified checkpoints on disk
- **THEN** it loads all verified checkpoints
- **AND** validates each checkpoint against its stored data
- **AND** initializes the tip from the latest checkpoint
- **AND** populates states metadata including any previously computed manifests

#### Scenario: Initialization with unverified checkpoints
- **WHEN** the State Manager starts and finds unverified checkpoints (from state sync or incomplete local writes)
- **THEN** it archives the unverified checkpoints to prevent using potentially inconsistent state
- **AND** proceeds with only verified checkpoints

#### Scenario: Initialization with starting height constraint
- **WHEN** a starting height is provided and checkpoints exist above that height
- **THEN** checkpoints newer than the starting height are archived (except the last one if it is the only checkpoint)
- **AND** the State Manager starts from the most recent checkpoint at or below the starting height

### Requirement: State Tip Management

The State Manager provides a mutable "tip" state that the state machine thread borrows and returns.

#### Scenario: Taking the tip
- **WHEN** `take_tip()` is called
- **THEN** the current tip state is returned along with its height
- **AND** the tip slot is marked as empty to prevent concurrent modification
- **AND** the `prev_state_hash` metadata is populated on the returned state

#### Scenario: Taking the tip after state sync advances
- **WHEN** `take_tip()` is called and a state sync has completed at a height above the current tip
- **THEN** the tip is re-initialized from the latest checkpoint snapshot
- **AND** the new tip height reflects the state sync checkpoint height

#### Scenario: Taking the tip at a specific height
- **WHEN** `take_tip_at(height)` is called
- **THEN** if the tip height matches, the state is returned
- **AND** if the requested height is below the tip, `StateRemoved` error is returned
- **AND** if the requested height is above the tip, `StateNotCommittedYet` error is returned

### Requirement: State Commit and Certification

After each round of execution, the state must be committed, hashed, and potentially checkpointed.

#### Scenario: Committing state with metadata scope
- **WHEN** `commit_and_certify` is called with `CertificationScope::Metadata`
- **THEN** the state is cloned and stored as a snapshot at the new height
- **AND** a hash tree is computed for certification
- **AND** the tip is updated to the new height
- **AND** no checkpoint is created on disk

#### Scenario: Committing state with full scope (checkpoint)
- **WHEN** `commit_and_certify` is called with `CertificationScope::Full`
- **THEN** a checkpoint is created on disk from the tip
- **AND** the state is switched to reference the checkpoint files
- **AND** a hash tree is computed for certification
- **AND** manifest computation is scheduled asynchronously on the tip thread
- **AND** metadata is persisted to disk
- **AND** checkpoint verification is scheduled asynchronously

#### Scenario: Skipping state cloning during catch-up
- **WHEN** `commit_and_certify` is called with `CertificationScope::Metadata`
- **AND** the node is catching up (height below fast_forward_height)
- **AND** the height is not a multiple of `MAX_CONSECUTIVE_ROUNDS_WITHOUT_STATE_CLONING` (10)
- **THEN** the state is stored as the tip without cloning or hashing
- **AND** no snapshot or certification metadata is created for this height

#### Scenario: Pre-checkpoint overlay flush
- **WHEN** `commit_and_certify` is called with `CertificationScope::Metadata`
- **AND** the height is exactly `NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY` (50) rounds before the next checkpoint
- **THEN** all canister page maps and snapshots are flushed to overlay files
- **AND** this reduces the amount of data that must be written during checkpoint creation

#### Scenario: Detecting state divergence at commit
- **WHEN** `commit_and_certify` produces a hash that differs from a previously computed or delivered hash for the same height
- **THEN** a diverged state marker is created on disk
- **AND** the replica panics with a divergence error

### Requirement: State Hash Retrieval

The State Manager must provide the state hash at any committed height.

#### Scenario: Hash available for committed checkpoint
- **WHEN** `get_state_hash_at(height)` is called for a checkpointed height with a computed manifest
- **THEN** the `CryptoHashOfState` is returned

#### Scenario: Hash not yet computed
- **WHEN** `get_state_hash_at(height)` is called for a committed height whose manifest is still being computed
- **THEN** a transient `HashNotComputedYet` error is returned

#### Scenario: Hash for uncommitted height
- **WHEN** `get_state_hash_at(height)` is called for a height not yet committed
- **THEN** a transient `StateNotCommittedYet` error is returned

#### Scenario: Hash for removed state
- **WHEN** `get_state_hash_at(height)` is called for a height older than the oldest kept state
- **THEN** a permanent `StateRemoved` error is returned

### Requirement: State Certification Delivery

Consensus delivers certifications to the State Manager, which uses them to produce certified state snapshots.

#### Scenario: Delivering a certification
- **WHEN** `deliver_state_certification` is called with a certification at a given height
- **THEN** the certification is stored for the corresponding height
- **AND** the `latest_certified_height` is updated
- **AND** hash trees for heights below the certified height are dropped to save memory
- **AND** old snapshots below the certified height (minus extra checkpoints to keep) are removed

#### Scenario: Optimistic certification delivery
- **WHEN** `deliver_state_certification` is called for a height that has not yet been committed
- **THEN** the certification is stored in the `certifications` map for later reconciliation
- **AND** when the state is eventually committed, the pre-delivered certification is attached

#### Scenario: Certification hash mismatch
- **WHEN** a delivered certification's hash differs from the locally computed hash
- **THEN** the state is marked as diverged
- **AND** a backup of the diverged checkpoint is created
- **AND** the replica enters a fatal error state

### Requirement: State Reading

The State Manager provides read access to committed states.

#### Scenario: Reading the latest state
- **WHEN** `get_latest_state()` is called
- **THEN** the most recent snapshot in memory is returned

#### Scenario: Reading state at a specific height
- **WHEN** `get_state_at(height)` is called
- **AND** the state is available as an in-memory snapshot
- **THEN** the snapshot is returned

#### Scenario: Falling back to checkpoint on disk
- **WHEN** `get_state_at(height)` is called
- **AND** the state is not in memory but exists as a checkpoint on disk
- **THEN** the checkpoint is loaded from disk and returned
- **AND** an error metric is incremented to track the fallback

#### Scenario: Reading certified state
- **WHEN** `read_certified_state` is called with a set of paths
- **THEN** the latest certified state is used
- **AND** the requested paths are materialized as a partial tree
- **AND** a witness (MixedHashTree) is generated from the hash tree
- **AND** the certification is included in the response

### Requirement: State Fetch via State Sync

The State Manager coordinates fetching state from peers when the node falls behind.

#### Scenario: Initiating state fetch
- **WHEN** `fetch_state(height, root_hash)` is called for a height not yet available locally
- **THEN** the fetch target is stored (height, hash, CUP interval length)
- **AND** the state sync protocol begins requesting chunks from peers

#### Scenario: State already exists locally with matching hash
- **WHEN** `fetch_state` is called and a local checkpoint with matching root hash exists
- **THEN** the checkpoint is cloned to the target height
- **AND** no network fetch is initiated

#### Scenario: Receiving a synced checkpoint
- **WHEN** state sync completes and delivers a checkpoint
- **THEN** the checkpoint is loaded and validated (or just loaded if recent checkpoints exist)
- **AND** the state is registered as a snapshot
- **AND** metadata is updated
- **AND** the tip is updated on the next `take_tip()` call

### Requirement: Diverged State Management

The State Manager handles state divergence gracefully.

#### Scenario: Reporting a diverged checkpoint
- **WHEN** `report_diverged_checkpoint(height)` is called
- **THEN** the checkpoint at that height is moved to the diverged checkpoints directory
- **AND** all checkpoints above the diverged height are removed
- **AND** metadata for removed checkpoints is cleared
- **AND** the replica enters a fatal error state

#### Scenario: Cleaning up old diverged states
- **WHEN** the State Manager initializes
- **THEN** diverged checkpoints and backups older than 30 days are removed
- **AND** at most `MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP` (1) archived checkpoints are retained
- **AND** at most `MAX_DIVERGED_STATE_MARKERS_TO_KEEP` (100) diverged markers are retained

### Requirement: Metadata Persistence

State metadata (manifests, etc.) is persisted to enable fast recovery.

#### Scenario: Persisting metadata after checkpoint
- **WHEN** a checkpoint is created or a manifest is computed
- **THEN** the states metadata is serialized to protobuf
- **AND** written atomically to `states_metadata.pbuf`
- **AND** a separate lock prevents concurrent metadata writes

#### Scenario: Loading metadata on startup
- **WHEN** the State Manager initializes
- **THEN** previously persisted metadata is loaded from `states_metadata.pbuf`
- **AND** manifests from metadata are reused to avoid recomputation
- **AND** if metadata is missing or corrupt, manifests are recomputed from checkpoints

### Requirement: Asynchronous Tip Thread

A dedicated background thread handles checkpoint operations, manifest computation, and overlay merging.

#### Scenario: Tip to checkpoint conversion
- **WHEN** a `TipToCheckpointAndSwitch` request is sent to the tip thread
- **THEN** the tip directory is renamed to a checkpoint
- **AND** protobuf files are serialized to the new checkpoint
- **AND** the result (new state and checkpoint layout) is sent back via channel

#### Scenario: Filtering tip canisters
- **WHEN** a `FilterTipCanisters` request is sent
- **THEN** canister and snapshot directories not in the provided sets are removed from the tip

#### Scenario: Flushing page map deltas
- **WHEN** a `FlushPageMapDelta` request is sent
- **THEN** dirty pages from each page map are written as overlay files to the tip directory

#### Scenario: Resetting tip and merging overlays
- **WHEN** a `ResetTipAndMerge` request is sent
- **THEN** the tip directory is reset to match the latest checkpoint (via reflink copy)
- **AND** overlay files in the tip are merged if necessary to control file count and disk usage

#### Scenario: Computing manifest
- **WHEN** a `ComputeManifest` request is sent
- **THEN** the manifest is computed for the checkpoint (reusing chunks from a base manifest when possible)
- **AND** the result is stored in states metadata
- **AND** metadata is persisted to disk

#### Scenario: Validating replicated state
- **WHEN** a `ValidateReplicatedStateAndFinalize` request is sent
- **THEN** the checkpoint is loaded and compared against the reference in-memory state
- **AND** if they differ, the replica crashes with a critical error
- **AND** if they match, the unverified checkpoint marker is removed

### Requirement: Overlay Merging Strategy

The tip thread merges overlay files to control storage overhead.

#### Scenario: Merge triggered by file count
- **WHEN** a page map shard has more than `NUMBER_OF_FILES_HARD_LIMIT` (20) overlay files
- **THEN** the shard is merged regardless of the soft budget

#### Scenario: Merge within soft budget
- **WHEN** the total estimated merge write size is within `MERGE_SOFT_BUDGET_BYTES` (250 GiB)
- **THEN** shards with the highest storage overhead are merged first
- **AND** merging stops once the budget is exhausted

### Requirement: Certified Stream Store

The State Manager provides certified stream slices for cross-subnet communication.

#### Scenario: Encoding a certified stream slice
- **WHEN** `encode_certified_stream_slice` is called for a remote subnet
- **THEN** the latest certified state is used
- **AND** the requested stream messages are encoded as a canonical labeled tree
- **AND** a Merkle witness is generated from the hash tree
- **AND** the result includes the payload, witness, and certification

#### Scenario: Decoding a certified stream slice
- **WHEN** `decode_certified_stream_slice` is called with a slice from a remote subnet
- **THEN** the certification signature is verified against the registry
- **AND** the witness is validated against the tree hash
- **AND** the stream header and messages are decoded from canonical CBOR form

#### Scenario: Decoding with invalid signature
- **WHEN** a certified stream slice has an invalid signature
- **THEN** a `DecodeStreamError` is returned
- **AND** a failure metric is recorded

#### Scenario: Decoding with hash mismatch
- **WHEN** the recomputed hash of the slice tree does not match the certification hash
- **THEN** a `DecodeStreamError` is returned
- **AND** a failure metric is recorded
