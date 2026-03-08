# Checkpoint Management

Checkpoints are persistent snapshots of the replicated state written to disk at regular intervals (every CUP interval). They serve as recovery points and the basis for state synchronization.

## Requirements

### Requirement: Checkpoint Creation

Checkpoints are created by converting the mutable tip state into an immutable checkpoint.

#### Scenario: Making a checkpoint from tip
- **WHEN** a checkpoint is created at a given height
- **THEN** all canister page maps are flushed to disk (overlay files)
- **AND** all canister snapshot page maps are flushed
- **AND** protobuf metadata files are serialized for each canister
- **AND** system metadata, ingress history, and subnet queues are serialized
- **AND** the tip directory is atomically renamed to a checkpoint
- **AND** the checkpoint is marked with an unverified marker until validation completes

#### Scenario: Parallel page map flushing
- **WHEN** page maps are flushed during checkpoint creation
- **THEN** flushing happens in parallel across up to 16 threads
- **AND** page maps marked for truncation have their storage reset before flushing
- **AND** page maps with no changes produce no output (tracked as empty_delta_writes)

#### Scenario: Checkpoint protobuf serialization
- **WHEN** protobuf files are written during checkpoint creation
- **THEN** `system_metadata.pbuf` contains subnet metadata and network topology
- **AND** `ingress_history.pbuf` contains the ingress history state
- **AND** `subnet_queues.pbuf` contains the subnet message queues
- **AND** each canister's `canister.pbuf` contains CanisterStateBits
- **AND** each canister's `queues.pbuf` contains the canister's message queues
- **AND** `stats.pbuf` contains statistics for the checkpoint

### Requirement: Checkpoint Loading

Checkpoints are loaded from disk back into in-memory `ReplicatedState`.

#### Scenario: Loading a checkpoint
- **WHEN** `load_checkpoint` is called for a checkpoint layout
- **THEN** system metadata is deserialized from `system_metadata.pbuf`
- **AND** ingress history is deserialized from `ingress_history.pbuf`
- **AND** subnet queues are deserialized from `subnet_queues.pbuf`
- **AND** each canister state is loaded in parallel
- **AND** the subnet type is applied from configuration

#### Scenario: Loading canister state
- **WHEN** a canister's state is loaded from a checkpoint
- **THEN** `canister.pbuf` is deserialized to reconstruct CanisterStateBits
- **AND** `queues.pbuf` is deserialized to reconstruct message queues
- **AND** if the canister has an execution state:
  - The Wasm binary is loaded from `software.wasm` (via mmap when possible)
  - Page maps are created for wasm_memory, stable_memory, wasm_chunk_store, and log_memory_store
  - Global variables are restored from execution state bits

#### Scenario: Loading canister snapshots
- **WHEN** canister snapshots exist in a checkpoint
- **THEN** each snapshot's `snapshot.pbuf` is deserialized
- **AND** the snapshot's Wasm binary and page maps are loaded
- **AND** snapshots are associated with their canister IDs

#### Scenario: Parallel canister loading
- **WHEN** multiple canisters exist in a checkpoint
- **THEN** canisters are loaded in parallel using up to 16 threads
- **AND** loading metrics are recorded per step (metadata deserialization, page map creation, etc.)

### Requirement: Checkpoint Validation

Checkpoints are validated after creation to ensure consistency between disk and memory state.

#### Scenario: Full validation and finalization
- **WHEN** `load_checkpoint_and_validate_parallel` is called
- **THEN** the checkpoint is loaded from disk
- **AND** all files in the checkpoint are marked read-only and synced
- **AND** page map storage is validated for consistency
- **AND** the unverified checkpoint marker is removed
- **AND** the checkpoint is promoted to verified status

#### Scenario: Post-creation state comparison
- **WHEN** `ValidateReplicatedStateAndFinalize` runs on the tip thread
- **THEN** the checkpoint is loaded from disk
- **AND** it is compared against the in-memory reference state using `ValidateEq`
- **AND** if a mismatch is detected, a critical error is raised and the replica crashes
- **AND** if validation succeeds, the checkpoint marker is removed

#### Scenario: Storage validation
- **WHEN** page map storage is validated during checkpoint loading
- **THEN** each page map's overlay files are checked for consistency
- **AND** file integrity is verified (correct headers, valid indices, etc.)

### Requirement: Wasm Binary Loading

Wasm binaries are loaded efficiently using memory mapping when possible.

#### Scenario: Memory-mapped Wasm loading
- **WHEN** a Wasm binary is loaded from a checkpoint
- **THEN** the file is first attempted to be memory-mapped (mmap)
- **AND** if mmap succeeds, the binary references the mapped file directly
- **AND** if mmap fails, the file is read into memory as a fallback
- **AND** the loading status (mmap vs. copy) is tracked in metrics

#### Scenario: Wasm binary deduplication
- **WHEN** multiple canisters or snapshots share the same Wasm binary hash
- **THEN** the `WasmBinary` instance is shared via `Arc`
- **AND** only one copy of the Wasm code exists in memory

### Requirement: Page Map Type Classification

Different types of page maps are classified for flushing and tracking.

#### Scenario: Canister page map types
- **WHEN** page map types are enumerated for a canister
- **THEN** the following types are identified:
  - `WasmMemory` (vmemory_0) - the Wasm heap memory
  - `StableMemory` (stable_memory) - the canister's stable memory
  - `WasmChunkStore` (wasm_chunk_store) - storage for uploaded Wasm chunks
  - `LogMemoryStore` (log_memory_store) - the canister's log memory

#### Scenario: Snapshot page map types
- **WHEN** page map types are enumerated for a snapshot
- **THEN** the following types are identified:
  - `SnapshotWasmMemory` - the snapshot's Wasm heap memory
  - `SnapshotStableMemory` - the snapshot's stable memory
  - `SnapshotWasmChunkStore` - the snapshot's chunk store

#### Scenario: Listing all page map types including snapshots
- **WHEN** `PageMapType::list_all_including_snapshots(state)` is called
- **THEN** all canister page map types for all canisters are included
- **AND** all snapshot page map types for all snapshots are included

### Requirement: Split Marker Handling

Checkpoints may contain a split marker indicating they resulted from a subnet split.

#### Scenario: Split marker presence
- **WHEN** a checkpoint was created from a subnet split
- **THEN** `split_from.pbuf` exists in the checkpoint directory
- **AND** it contains the original subnet ID that was split

#### Scenario: Loading a split checkpoint
- **WHEN** a checkpoint with a split marker is loaded
- **THEN** the `SplitFrom` metadata is read and stored in system metadata
- **AND** this information is used to properly initialize the split subnet's state
