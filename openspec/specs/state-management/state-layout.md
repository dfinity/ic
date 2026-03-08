# State Layout

**Crates**: `ic-state-layout`

The State Layout manages the on-disk directory structure for the Internet Computer's replicated state, including checkpoints, the mutable tip, backups, and diverged states.

## Requirements

### Requirement: Directory Structure

The State Layout enforces a well-defined directory hierarchy for all state artifacts.

#### Scenario: Root directory structure
- **WHEN** a StateLayout is created
- **THEN** the root directory contains the following structure:
  - `states_metadata.pbuf` - persisted metadata
  - `tip/` - mutable working state
  - `checkpoints/` - verified and unverified checkpoints by height
  - `backups/` - archived checkpoints
  - `diverged_checkpoints/` - checkpoints that diverged from consensus
  - `diverged_state_markers/` - markers for diverged states
  - `tmp/` - temporary files for atomic writes
  - `fs_tmp/` - scratch space for state sync
  - `page_deltas/` - file-backed memory allocator directory

#### Scenario: Checkpoint directory structure
- **WHEN** a checkpoint exists at a given height
- **THEN** the checkpoint directory contains:
  - `system_metadata.pbuf` - subnet-level metadata
  - `subnet_queues.pbuf` - subnet message queues
  - `ingress_history.pbuf` - ingress message history
  - `split_from.pbuf` - marker for subnet split origin (optional)
  - `stats.pbuf` - statistics (optional)
  - `canister_states/` - per-canister directories
  - `snapshots/` - canister snapshot directories

#### Scenario: Canister directory structure
- **WHEN** a canister state directory exists
- **THEN** it contains:
  - `canister.pbuf` - canister metadata and execution state bits
  - `queues.pbuf` - canister message queues
  - `software.wasm` - Wasm module binary
  - `vmemory_0.bin` or overlay files - Wasm heap memory
  - `stable_memory.bin` or overlay files - stable memory
  - `wasm_chunk_store.bin` or overlay files - chunk store data
  - `log_memory_store.bin` or overlay files - log memory data

#### Scenario: Snapshot directory structure
- **WHEN** a canister snapshot directory exists
- **THEN** it is organized as `snapshots/<canister_id>/<snapshot_id>/`
- **AND** contains:
  - `snapshot.pbuf` - snapshot metadata
  - `software.wasm` - Wasm module binary
  - `vmemory_0.bin` or overlay files - Wasm heap memory
  - `stable_memory.bin` or overlay files - stable memory

### Requirement: Access Policies

The State Layout enforces type-safe access policies for reading and writing.

#### Scenario: ReadOnly access
- **WHEN** a `CheckpointLayout<ReadOnly>` is used
- **THEN** only read operations are permitted
- **AND** directory existence is not enforced (errors occur naturally on missing reads)

#### Scenario: WriteOnly access
- **WHEN** a `CheckpointLayout<WriteOnly>` is used
- **THEN** directories are created on first access if they do not exist

#### Scenario: ReadWrite access for tip
- **WHEN** a `CheckpointLayout<RwPolicy>` is used (for the tip)
- **THEN** both read and write operations are permitted
- **AND** directories are created on first access

### Requirement: Checkpoint Lifecycle

The State Layout manages the creation, verification, and removal of checkpoints.

#### Scenario: Creating a checkpoint from the tip
- **WHEN** `tip_to_checkpoint` is called
- **THEN** the tip directory is atomically renamed to a checkpoint directory under `checkpoints/<height>/`
- **AND** the checkpoint directory is synced to disk
- **AND** an unverified checkpoint marker file is created

#### Scenario: Checkpoint verification status
- **WHEN** a checkpoint is queried for its status
- **THEN** if no marker files exist, it is `Verified`
- **AND** if `unverified_checkpoint_marker` exists but not `state_sync_checkpoint_marker`, it is `UnverifiedRegular`
- **AND** if both markers exist, it is `UnverifiedStateSync`

#### Scenario: Listing verified checkpoint heights
- **WHEN** `verified_checkpoint_heights()` is called
- **THEN** only checkpoints without any marker files are returned
- **AND** heights are returned in sorted order

#### Scenario: Listing unfiltered checkpoint heights
- **WHEN** `unfiltered_checkpoint_heights()` is called
- **THEN** all checkpoints (verified and unverified) are returned

#### Scenario: Removing a checkpoint
- **WHEN** `remove_checkpoint(height)` is called
- **THEN** the checkpoint directory is moved to a temporary location
- **AND** actual deletion happens asynchronously in a background thread
- **AND** a reference counting mechanism ensures no active `CheckpointLayout` references exist

#### Scenario: Archiving a checkpoint
- **WHEN** `archive_checkpoint(height)` is called
- **THEN** the checkpoint is moved from `checkpoints/` to `backups/`
- **AND** it is no longer visible in `verified_checkpoint_heights()`

#### Scenario: Marking a checkpoint as diverged
- **WHEN** `mark_checkpoint_diverged(height)` is called
- **THEN** the checkpoint is moved from `checkpoints/` to `diverged_checkpoints/`

#### Scenario: Cloning a checkpoint
- **WHEN** `clone_checkpoint(src_height, dst_height)` is called
- **THEN** the source checkpoint directory is recursively copied to the destination height
- **AND** files are reflinked where possible for efficiency
- **AND** the destination is synced to disk

### Requirement: Tip Management

The tip directory holds the mutable state being modified during round execution.

#### Scenario: Capturing the tip handler
- **WHEN** `capture_tip_handler()` is called
- **THEN** a `TipHandler` is returned that has exclusive ownership of the tip directory
- **AND** it can only be captured once (subsequent calls panic)

#### Scenario: Resetting tip to a checkpoint
- **WHEN** `reset_tip_to(checkpoint)` is called on the `TipHandler`
- **THEN** the existing tip directory is removed
- **AND** the checkpoint is copied to the tip directory
- **AND** protobuf files are skipped during copy (they are written separately)
- **AND** binary files are reflinked as read-only

#### Scenario: Filtering tip canisters
- **WHEN** `filter_tip_canisters(height, ids)` is called
- **THEN** canister directories in the tip that are not in the provided set are deleted

#### Scenario: Filtering tip snapshots
- **WHEN** `filter_tip_snapshots(height, ids)` is called
- **THEN** snapshot directories in the tip that are not in the provided set are deleted

### Requirement: State Sync Scratchpad

The State Layout provides scratch space for state sync operations.

#### Scenario: Creating a state sync scratchpad
- **WHEN** state sync starts for a given height
- **THEN** a scratchpad directory is created at `fs_tmp/state_sync_scratchpad_<height>`
- **AND** state files are written directly into this directory

#### Scenario: Promoting scratchpad to checkpoint
- **WHEN** state sync completes for a height
- **THEN** `mark_files_readonly_and_sync()` is called on the scratchpad to sync all files
- **AND** the scratchpad is renamed to `checkpoints/<height>`
- **AND** the checkpoints directory is synced

### Requirement: Checkpoint Reference Counting

The State Layout tracks active references to checkpoints to prevent premature deletion.

#### Scenario: Creating a checkpoint layout increments the reference
- **WHEN** a `CheckpointLayout<ReadOnly>` is created for a height
- **THEN** the reference count for that height is incremented

#### Scenario: Dropping a checkpoint layout decrements the reference
- **WHEN** a `CheckpointLayout<ReadOnly>` is dropped
- **THEN** the reference count for that height is decremented
- **AND** if the count reaches zero and the checkpoint is marked for deletion, it is removed

#### Scenario: Scheduling deletion of a referenced checkpoint
- **WHEN** `remove_checkpoint` is called for a height with active references
- **THEN** the checkpoint is marked for deletion
- **AND** actual removal is deferred until all references are dropped

### Requirement: Page Map Storage Layout

The State Layout provides the storage layout for page maps (overlay and base files).

#### Scenario: Canister page map layout
- **WHEN** the storage layout for a canister's page map (e.g., vmemory_0, stable_memory) is requested
- **THEN** the layout returns paths for the base file and existing overlay files
- **AND** overlays are ordered by height

#### Scenario: Snapshot page map layout
- **WHEN** the storage layout for a snapshot's page map is requested
- **THEN** the layout includes the appropriate base and overlay file paths under the snapshot directory

### Requirement: File Marking and Syncing

The State Layout supports marking files as read-only and syncing them to disk.

#### Scenario: Marking checkpoint files read-only
- **WHEN** `mark_files_readonly_and_sync()` is called on a checkpoint layout
- **THEN** all regular files in the checkpoint directory tree are set to read-only permissions
- **AND** all files and directories are synced to disk
- **AND** a count of traversed and modified files is returned

#### Scenario: Startup readonly marking
- **WHEN** the State Manager initializes
- **THEN** `mark_checkpoint_files_readonly()` is called on all existing checkpoints
- **AND** this corrects any permission changes made by init scripts during upgrades

### Requirement: Protobuf Serialization

Canister and system state bits are serialized/deserialized via protobuf.

#### Scenario: CanisterStateBits roundtrip
- **WHEN** a `CanisterStateBits` is serialized to `canister.pbuf`
- **AND** later deserialized
- **THEN** all fields (controllers, cycles_balance, status, execution_state_bits, etc.) are preserved

#### Scenario: CanisterSnapshotBits roundtrip
- **WHEN** a `CanisterSnapshotBits` is serialized to `snapshot.pbuf`
- **AND** later deserialized
- **THEN** all fields (snapshot_id, canister_id, binary_hash, certified_data, etc.) are preserved

#### Scenario: ExecutionStateBits roundtrip
- **WHEN** an `ExecutionStateBits` is serialized
- **AND** later deserialized
- **THEN** exported globals, heap size, exports, binary hash, and metadata are preserved
