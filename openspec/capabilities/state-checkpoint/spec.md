# State: Checkpoint Management Capability Specification

**Source narrative**: `openspec/specs/state-management/checkpoint.md`
**Crates**: `ic-state-manager`
**Key files**: `rs/state_manager/src/checkpoint.rs`, `rs/state_manager/src/tip.rs`

---

## REQ-CKPT-001: Checkpoint Creation

Checkpoints MUST be created by converting the mutable tip state into an immutable on-disk snapshot.

### SCENARIO-CKPT-001: Making a checkpoint from tip
**Given** a checkpoint is created at a given height
**When** the creation runs
**Then** all canister page maps are flushed to disk as overlay files
**And** all canister snapshot page maps are flushed
**And** protobuf metadata files are serialized for each canister
**And** system metadata, ingress history, and subnet queues are serialized
**And** the tip directory is atomically renamed to a checkpoint
**And** the checkpoint is marked with an unverified marker until validation completes

### SCENARIO-CKPT-002: Parallel page map flushing
**Given** page maps are flushed during checkpoint creation
**When** flushing runs
**Then** flushing happens in parallel across up to 16 threads
**And** page maps marked for truncation have their storage reset before flushing
**And** page maps with no changes produce no output

### SCENARIO-CKPT-003: Checkpoint protobuf files
**Given** protobuf files are written during checkpoint creation
**When** serialization runs
**Then** `system_metadata.pbuf` contains subnet metadata and network topology
**And** `ingress_history.pbuf` contains ingress history state
**And** `subnet_queues.pbuf` contains subnet message queues
**And** each canister's `canister.pbuf` contains `CanisterStateBits`
**And** each canister's `queues.pbuf` contains the canister's message queues

---

## REQ-CKPT-002: Checkpoint Loading

Checkpoints MUST be loadable from disk back into in-memory `ReplicatedState`.

### SCENARIO-CKPT-004: Loading a checkpoint
**Given** `load_checkpoint` is called for a checkpoint layout
**When** loading runs
**Then** system metadata, ingress history, and subnet queues are deserialized
**And** each canister state is loaded in parallel
**And** the subnet type is applied from configuration

### SCENARIO-CKPT-005: Loading canister state from checkpoint
**Given** a canister's state is loaded from a checkpoint
**When** loading runs
**Then** `canister.pbuf` and `queues.pbuf` are deserialized
**And** the Wasm binary is loaded from `software.wasm` (via mmap when possible)
**And** page maps are created for wasm_memory, stable_memory, wasm_chunk_store, and log_memory_store

### SCENARIO-CKPT-006: Parallel canister loading
**Given** multiple canisters exist in a checkpoint
**When** loading runs
**Then** canisters are loaded in parallel using up to 16 threads
**And** loading metrics are recorded per step

---

## REQ-CKPT-003: Checkpoint Validation

Checkpoints MUST be validated after creation to ensure consistency.

### SCENARIO-CKPT-007: Full validation and finalization
**Given** `load_checkpoint_and_validate_parallel` is called
**When** validation runs
**Then** the checkpoint is loaded from disk
**And** all files are marked read-only and synced
**And** page map storage is validated for consistency
**And** the unverified checkpoint marker is removed
**And** the checkpoint is promoted to verified status

### SCENARIO-CKPT-008: Post-creation state comparison
**Given** `ValidateReplicatedStateAndFinalize` runs on the tip thread
**When** comparison runs
**Then** the checkpoint is loaded from disk and compared against the in-memory reference state
**And** if a mismatch is detected, a critical error is raised and the replica crashes
**And** if validation succeeds, the checkpoint marker is removed

---

## REQ-CKPT-004: Wasm Binary Loading

Wasm binaries MUST be loaded efficiently using memory mapping when possible.

### SCENARIO-CKPT-009: Memory-mapped Wasm loading
**Given** a Wasm binary is loaded from a checkpoint
**When** loading runs
**Then** mmap is attempted first
**And** if mmap succeeds, the binary references the mapped file directly
**And** if mmap fails, the file is read into memory as a fallback

### SCENARIO-CKPT-010: Wasm binary deduplication
**Given** multiple canisters or snapshots share the same Wasm binary hash
**When** loading runs
**Then** the `WasmBinary` instance is shared via `Arc`
**And** only one copy of the Wasm code exists in memory

---

## REQ-CKPT-005: Page Map Type Classification

Different page map types MUST be correctly classified for flushing and tracking.

### SCENARIO-CKPT-011: Canister page map types
**Given** page map types are enumerated for a canister
**When** enumeration runs
**Then** the following types are identified: `WasmMemory`, `StableMemory`, `WasmChunkStore`, `LogMemoryStore`

### SCENARIO-CKPT-012: Snapshot page map types
**Given** page map types are enumerated for a snapshot
**When** enumeration runs
**Then** the following types are identified: `SnapshotWasmMemory`, `SnapshotStableMemory`, `SnapshotWasmChunkStore`

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
## REQ-CKPT-006: Split Marker Handling

Checkpoints resulting from subnet splits MUST carry a split marker.

### SCENARIO-CKPT-013: Split marker presence in checkpoint
**Given** a checkpoint was created from a subnet split
**When** the checkpoint directory is examined
**Then** `split_from.pbuf` exists containing the original subnet ID that was split

### SCENARIO-CKPT-014: Loading a split checkpoint
**Given** a checkpoint with a split marker is loaded
**When** loading runs
**Then** the `SplitFrom` metadata is read and stored in system metadata
**And** this information is used to properly initialize the split subnet's state

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-CKPT-001 | Checkpoint creation | linked | rs/state_manager/src/checkpoint.rs |
| REQ-CKPT-002 | Checkpoint loading | linked | rs/state_manager/src/checkpoint.rs |
| REQ-CKPT-003 | Checkpoint validation | narrative | rs/state_manager/tests/ |
| REQ-CKPT-004 | Wasm binary loading | narrative | rs/state_manager/tests/ |
| REQ-CKPT-005 | Page map types | narrative | rs/state_manager/tests/ |
