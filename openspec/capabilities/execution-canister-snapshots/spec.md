# Execution: Canister Snapshots Capability Specification

**Source narrative**: `openspec/specs/execution/canister-snapshots.md`
**Crates**: `ic-execution-environment`
**Key files**: `rs/execution_environment/src/canister_manager.rs`

---

## REQ-SNAP-001: Taking Canister Snapshots

Controllers MUST be able to create snapshots of canister state.

### SCENARIO-SNAP-001: Successful snapshot creation
**Given** `take_canister_snapshot` is called by a controller
**When** the snapshot is created
**Then** it includes execution state (Wasm memory, stable memory, globals), system state metadata, and certified data
**And** a unique `SnapshotId` is returned
**And** instructions are charged based on baseline cost plus data size

### SCENARIO-SNAP-002: Snapshot with replacement
**Given** `take_canister_snapshot` is called with an existing `snapshot_id`
**When** the replacement runs
**Then** the old snapshot is deleted and replaced with the new one

### SCENARIO-SNAP-003: Snapshot limit per canister
**Given** the number of snapshots reaches `max_number_of_snapshots_per_canister`
**When** a new snapshot is attempted without a replacement ID
**Then** the creation fails

---

## REQ-SNAP-002: Loading Canister Snapshots

Controllers MUST be able to restore canister state from a snapshot.

### SCENARIO-SNAP-004: Successful snapshot load
**Given** `load_canister_snapshot` is called with a valid snapshot ID
**When** the load runs
**Then** the canister's execution state, memory, and globals are replaced from the snapshot
**And** the canister version is bumped

### SCENARIO-SNAP-005: Load from different canister fails
**Given** `load_canister_snapshot` is called with a snapshot belonging to a different canister
**When** validation runs
**Then** the operation fails with an error

---

## REQ-SNAP-003: Snapshot Data Transfer

Snapshot data MUST be uploadable and downloadable in chunks for large snapshots.

### SCENARIO-SNAP-006: Read snapshot data
**Given** `read_canister_snapshot_data` is called with offset and length
**When** the read runs
**Then** the requested portion is returned (max slice size: 2,000,000 bytes)

### SCENARIO-SNAP-007: Upload snapshot data
**Given** `upload_canister_snapshot_data` is called with data chunks
**When** the upload runs
**Then** the data is written to the snapshot at the specified offset

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SNAP-001 | Taking snapshots | linked | rs/execution_environment/tests/canister_snapshots.rs |
| REQ-SNAP-002 | Loading snapshots | narrative | rs/execution_environment/tests/ |
| REQ-SNAP-003 | Data transfer | narrative | rs/execution_environment/tests/ |
