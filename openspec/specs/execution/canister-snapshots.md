# Canister Snapshots

This specification covers the canister snapshot functionality for backup and restore of canister state.

## Requirements

### Requirement: Taking Canister Snapshots

Controllers can create snapshots of a canister's state.

#### Scenario: Successful snapshot creation
- **WHEN** `take_canister_snapshot` is called by a controller
- **THEN** a snapshot of the canister's current state is created
- **AND** the snapshot includes execution state (Wasm memory, stable memory, globals), system state metadata, and certified data
- **AND** a unique `SnapshotId` is returned
- **AND** instructions are charged based on baseline cost plus data size

#### Scenario: Snapshot with replacement
- **WHEN** `take_canister_snapshot` is called with an existing `snapshot_id` to replace
- **THEN** the specified snapshot is replaced with the new snapshot
- **AND** the old snapshot is deleted

#### Scenario: Snapshot limit per canister
- **WHEN** the number of snapshots for a canister reaches `max_number_of_snapshots_per_canister`
- **THEN** creating additional snapshots fails unless a replacement snapshot_id is provided

#### Scenario: Snapshot decode failure
- **WHEN** `take_canister_snapshot` is called with invalid arguments
- **THEN** the request is rejected with a decode error

### Requirement: Loading Canister Snapshots

Controllers can restore a canister from a snapshot.

#### Scenario: Successful snapshot load
- **WHEN** `load_canister_snapshot` is called with a valid snapshot ID
- **THEN** the canister's state is restored from the snapshot
- **AND** the canister's execution state, memory, and globals are replaced
- **AND** the canister version is bumped

#### Scenario: Load snapshot from different canister
- **WHEN** `load_canister_snapshot` is called with a snapshot ID that belongs to a different canister
- **THEN** the operation fails with an error

### Requirement: Listing Canister Snapshots

Controllers can list available snapshots.

#### Scenario: List snapshots
- **WHEN** `list_canister_snapshots` is called
- **THEN** all snapshots for the canister are returned with their IDs, timestamps, and sizes

### Requirement: Deleting Canister Snapshots

Controllers can delete snapshots they no longer need.

#### Scenario: Successful snapshot deletion
- **WHEN** `delete_canister_snapshot` is called with a valid snapshot ID
- **THEN** the snapshot is removed
- **AND** the memory used by the snapshot is freed

#### Scenario: Delete non-existent snapshot
- **WHEN** `delete_canister_snapshot` is called with an invalid snapshot ID
- **THEN** the operation fails with an appropriate error

### Requirement: Canister Snapshot Data Upload and Download

Snapshot data can be uploaded and downloaded in chunks for large snapshots.

#### Scenario: Read snapshot data
- **WHEN** `read_canister_snapshot_data` is called with offset and length
- **THEN** the requested portion of snapshot data is returned
- **AND** the maximum slice size per download is 2,000,000 bytes

#### Scenario: Upload snapshot data
- **WHEN** `upload_canister_snapshot_data` is called with data chunks
- **THEN** the data is written to the snapshot at the specified offset

#### Scenario: Read snapshot metadata
- **WHEN** `read_canister_snapshot_metadata` is called
- **THEN** the snapshot's metadata (size, type, etc.) is returned

#### Scenario: Upload snapshot metadata
- **WHEN** `upload_canister_snapshot_metadata` is called
- **THEN** the snapshot's metadata is updated

### Requirement: Snapshot Instruction Charging

Snapshot operations are charged based on their computational cost.

#### Scenario: Baseline instruction charge
- **WHEN** a snapshot operation is performed
- **THEN** a baseline instruction cost (`canister_snapshot_baseline_instructions`) is charged

#### Scenario: Data-proportional instruction charge
- **WHEN** snapshot data is read or written
- **THEN** additional instructions proportional to the data size are charged (`canister_snapshot_data_baseline_instructions`)
