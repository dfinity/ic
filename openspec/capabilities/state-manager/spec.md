# State Manager Capability Specification

**Source narrative**: `openspec/specs/state-management/state-manager.md`
**Crates**: `ic-state-manager`, `ic-state-sync-manager`
**Key files**: `rs/state_manager/src/lib.rs`, `rs/state_manager/src/tip.rs`

---

## REQ-STMGR-001: State Initialization

The State Manager MUST initialize correctly from persisted checkpoints on disk.

### SCENARIO-STMGR-001: Fresh initialization with no checkpoints
**Given** the State Manager is created with no existing checkpoints on disk
**When** initialization runs
**Then** it initializes with a default state at height 0
**And** the tip is set to the initial state

### SCENARIO-STMGR-002: Initialization with existing verified checkpoints
**Given** the State Manager is created with existing verified checkpoints
**When** initialization runs
**Then** all verified checkpoints are loaded and validated
**And** the tip is initialized from the latest checkpoint
**And** previously computed manifests are populated in states metadata

### SCENARIO-STMGR-003: Initialization archives unverified checkpoints
**Given** the State Manager starts and finds unverified checkpoints
**When** initialization runs
**Then** unverified checkpoints are archived to prevent use
**And** only verified checkpoints are used

### SCENARIO-STMGR-004: Initialization with starting height constraint
**Given** a starting height is provided and checkpoints exist above it
**When** initialization runs
**Then** checkpoints newer than the starting height are archived
**And** the State Manager starts from the most recent checkpoint at or below starting height

---

## REQ-STMGR-002: State Tip Management

The State Manager MUST provide a mutable tip state for the state machine thread.

### SCENARIO-STMGR-005: Taking the tip
**Given** `take_tip()` is called
**When** the tip is taken
**Then** the current tip state is returned with its height
**And** the tip slot is marked empty to prevent concurrent modification
**And** `prev_state_hash` metadata is populated on the returned state

### SCENARIO-STMGR-006: Taking tip after state sync advances
**Given** `take_tip()` is called and a state sync completed at a height above the current tip
**When** the tip is taken
**Then** the tip is re-initialized from the latest checkpoint snapshot
**And** the new tip height reflects the state sync checkpoint height

### SCENARIO-STMGR-007: Taking tip at specific height
**Given** `take_tip_at(height)` is called
**When** the height is checked
**Then** if height matches tip, the state is returned
**And** if height < tip, `StateRemoved` error is returned
**And** if height > tip, `StateNotCommittedYet` error is returned

---

## REQ-STMGR-003: State Commit and Certification

After each execution round, the state MUST be committed, hashed, and optionally checkpointed.

### SCENARIO-STMGR-008: Commit with metadata scope
**Given** `commit_and_certify` is called with `CertificationScope::Metadata`
**When** commit runs
**Then** the state is cloned and stored as a snapshot at the new height
**And** a hash tree is computed for certification
**And** the tip is updated to the new height
**And** no checkpoint is created on disk

### SCENARIO-STMGR-009: Commit with full scope (checkpoint)
**Given** `commit_and_certify` is called with `CertificationScope::Full`
**When** commit runs
**Then** a checkpoint is created on disk from the tip
**And** the state references checkpoint files
**And** manifest computation is scheduled asynchronously
**And** metadata is persisted to disk

### SCENARIO-STMGR-010: Skip cloning during catch-up
**Given** `commit_and_certify` is called with metadata scope during catch-up
**And** the height is not a multiple of `MAX_CONSECUTIVE_ROUNDS_WITHOUT_STATE_CLONING (10)`
**When** commit runs
**Then** the state is stored as the tip without cloning or hashing
**And** no snapshot or certification metadata is created

### SCENARIO-STMGR-011: Pre-checkpoint overlay flush
**Given** the height is exactly `NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY (50)` rounds before the next checkpoint
**When** commit with metadata scope runs
**Then** all canister page maps and snapshots are flushed to overlay files
**And** this reduces data written during checkpoint creation

### SCENARIO-STMGR-012: Detect state divergence at commit
**Given** `commit_and_certify` produces a hash differing from a previously computed hash for the same height
**When** divergence is detected
**Then** a diverged state marker is created on disk
**And** the replica panics with a divergence error

---

## REQ-STMGR-004: State Hash Retrieval

The State Manager MUST provide the state hash at any committed height.

### SCENARIO-STMGR-013: Hash available for checkpointed height
**Given** `get_state_hash_at(height)` is called for a checkpointed height with computed manifest
**When** the hash is retrieved
**Then** the `CryptoHashOfState` is returned

### SCENARIO-STMGR-014: Hash not yet computed
**Given** `get_state_hash_at(height)` is called for a height whose manifest is still computing
**When** the hash is requested
**Then** a transient `HashNotComputedYet` error is returned

### SCENARIO-STMGR-015: Hash for removed state
**Given** `get_state_hash_at(height)` is called for a height older than the oldest kept state
**When** the hash is requested
**Then** a permanent `StateRemoved` error is returned

---

## REQ-STMGR-005: State Certification Delivery

Consensus certifications MUST be delivered to produce certified state snapshots.

### SCENARIO-STMGR-016: Delivering a certification
**Given** `deliver_state_certification` is called with a certification
**When** the certification is delivered
**Then** it is stored for the corresponding height
**And** `latest_certified_height` is updated
**And** hash trees below certified height are dropped to save memory
**And** old snapshots below certified height are removed

### SCENARIO-STMGR-017: Optimistic certification delivery
**Given** a certification is delivered for a height not yet committed
**When** the certification is stored
**Then** it is stored in the `certifications` map for later reconciliation
**And** when the state is eventually committed, the pre-delivered certification is attached

### SCENARIO-STMGR-018: Certification hash mismatch
**Given** a delivered certification's hash differs from the locally computed hash
**When** the mismatch is detected
**Then** the state is marked as diverged
**And** a backup of the diverged checkpoint is created
**And** the replica enters a fatal error state

---

## REQ-STMGR-006: State Reading

The State Manager MUST provide read access to committed states.

### SCENARIO-STMGR-019: Reading the latest state
**Given** `get_latest_state()` is called
**When** the state is retrieved
**Then** the most recently committed snapshot in memory is returned

### SCENARIO-STMGR-020: Falling back to checkpoint on disk
**Given** `get_state_at(height)` is called for a height not in memory but existing on disk
**When** the state is retrieved
**Then** the checkpoint is loaded from disk and returned
**And** an error metric is incremented to track the fallback

### SCENARIO-STMGR-021: Reading certified state
**Given** `read_certified_state` is called with a set of paths
**When** the state is read
**Then** the latest certified state is used
**And** requested paths are materialized as a partial tree
**And** a witness (MixedHashTree) is generated
**And** the certification is included in the response

---

## REQ-STMGR-007: State Sync (Fetch)

The State Manager MUST coordinate fetching state from peers when the node falls behind.

### SCENARIO-STMGR-022: Initiating state fetch
**Given** `fetch_state(height, root_hash)` is called for a height not yet available locally
**When** fetch is initiated
**Then** the fetch target is stored (height, hash, CUP interval length)
**And** the state sync protocol begins requesting chunks from peers

### SCENARIO-STMGR-023: Local checkpoint matches hash
**Given** `fetch_state` is called and a local checkpoint with matching root hash exists
**When** the match is found
**Then** the checkpoint is cloned to the target height
**And** no network fetch is initiated

---

## REQ-STMGR-008: Diverged State Management

The State Manager MUST handle state divergence gracefully.

### SCENARIO-STMGR-024: Reporting a diverged checkpoint
**Given** `report_diverged_checkpoint(height)` is called
**When** the report is processed
**Then** the checkpoint at that height is moved to the diverged checkpoints directory
**And** all checkpoints above the diverged height are removed
**And** the replica enters a fatal error state

### SCENARIO-STMGR-025: Cleaning old diverged states on startup
**Given** the State Manager initializes
**When** cleanup runs
**Then** diverged checkpoints older than 30 days are removed
**And** at most `MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP (1)` archived checkpoints are retained

---

## REQ-STMGR-009: Certified Stream Store

The State Manager MUST provide certified stream slices for cross-subnet communication.

### SCENARIO-STMGR-026: Encoding a certified stream slice
**Given** `encode_certified_stream_slice` is called for a remote subnet
**When** encoding runs
**Then** the latest certified state is used
**And** requested stream messages are encoded as a canonical labeled tree
**And** a Merkle witness is generated from the hash tree
**And** the result includes the payload, witness, and certification

### SCENARIO-STMGR-027: Decoding with invalid signature
**Given** a certified stream slice has an invalid signature
**When** decoding runs
**Then** a `DecodeStreamError` is returned
**And** a failure metric is recorded

### SCENARIO-STMGR-028: Decoding with hash mismatch
**Given** the recomputed hash does not match the certification hash
**When** decoding runs
**Then** a `DecodeStreamError` is returned and a failure metric is recorded

---

## REQ-STMGR-010: Overlay Merge Strategy

The tip thread MUST merge overlay files to control storage overhead.

### SCENARIO-STMGR-029: Merge triggered by file count (hard limit)
**Given** a page map shard has more than `NUMBER_OF_FILES_HARD_LIMIT` (20) overlay files
**When** the merge check runs
**Then** the shard is merged regardless of the soft budget

### SCENARIO-STMGR-030: Merge within soft budget
**Given** the total estimated merge write size is within `MERGE_SOFT_BUDGET_BYTES` (250 GiB)
**When** merges are scheduled
**Then** shards with the highest storage overhead are merged first
**And** merging stops once the budget is exhausted

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-STMGR-001 | Initialization | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-002 | Tip management | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-003 | Commit/checkpoint | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-004 | Hash retrieval | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-005 | Certification delivery | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-006 | State reading | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-007 | State sync/fetch | linked | rs/state_manager/tests/state_manager.rs |
| REQ-STMGR-008 | Diverged state | narrative | rs/state_manager/tests/ |
| REQ-STMGR-009 | Certified streams | narrative | rs/state_manager/tests/ |
| REQ-STMGR-010 | Overlay merge strategy | narrative | rs/state_manager/tests/ |
