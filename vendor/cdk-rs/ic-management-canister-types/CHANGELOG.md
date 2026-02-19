# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.6.0] - 2026-01-09

### Changed

- Added `uninstall_code` and `sender_canister_version` fields to `TakeCanisterSnapshotArgs`.
- Added `rename_canister` variant to `ChangeDetails`.
  - Added the types `RenameCanisterRecord` and `RenameToRecord`.

## [0.5.0] - 2025-11-13

### Changed

- Removed `SettingsChange` variant from `ChangeDetails`.
- Added `from_cansiter_id` field to `LoadSnapshotRecord`.
- Added `ready_for_migration` and `version` fields to `CanisterStatusResult`.
- Added `registry_version` field to `SubnetInfoResult`.

Following changes are for the Candid interface changes proposed in this [forum post](https://forum.dfinity.org/t/proposal-making-variant-fields-optional-for-schema-evolution/57898#p-203913-proposed-solution-2).
- The `details` field in `Change` is optional.
- The `source` and `globals` fields in `ReadCanisterSnapshotMetadataResult` are optional.

### Added

- `CanisterMetadataArgs` and `CanisterMetadataResult` for the new method `canister_metadata`.

## [0.4.1] - 2025-09-04

### Fixed

- Used `candid:Reserved` inside `TakenFromCanister` and `MetadataUpload` variants in `SnapshotSource`.
- Renamed `MainMemory` to `WasmMemory` in `SnapshotDataKind` and `SnapshotDataOffset`.
- Added `source` field to `LoadSnapshotRecord`.

While this is technically a breaking change in the Rust type system, we are treating it as a patch fix.
This is because the affected types and methods are for new, unreleased features (snapshot download/upload).
Therefore, no existing services or canisters should be impacted by this change.

## [0.4.0] - 2025-08-25

### Changed

- Added `environment_variable` field to `CanisterSettings` and `DefiniteCanisterSettings`.
  - Added the type `EnvironmentVariable`.
- Added `settings_change` variant to `ChangeDetails`.
- Added `environment_variables_hash` field to `CreationRecord`.
- Added `is_replicated` field to `HttpRequestArgs`.

## [0.3.3] - 2025-08-20

### Fixed

- The `exported_globals` field in the `ReadCanisterSnapshotMetadataResult` and `UploadCanisterSnapshotMetadataArgs` structs has been renamed to `globals`.
- The associated type `ExportedGlobal` has been renamed to `SnapshotMetadataGlobal`.

While this is technically a breaking change in the Rust type system, we are treating it as a patch fix.
This is because the affected types and methods are for new, unreleased features (snapshot download/upload).
Therefore, no existing services or canisters should be impacted by this change.

## [0.3.2] - 2025-07-25

### Added

- Types for canister snapshot download/upload.

## [0.3.1] - 2025-05-09

### Added

- Types for `vetkd_public_key` and `vetkd_derive_key`.

## [0.3.0] - 2025-03-17

### Changed

- Added `wasm_memory_threshold` field to `CanisterSettings` and `DefiniteCanisterSettings`.
- Added the `memory_metrics` field to `CanisterStatusResult`.
  - Added the type `MemoryMetrics`.

### Added

- Implemented trait that convert from `EcdsaCurve` and `SchnorrAlgorithm` into `u32`.

## [0.2.1] - 2025-02-28

### Added

- Types for `fetch_canister_logs`.
- `CanisterIdRecord`, an alias for various argument and result types to enhance inter-operability.

### Fixed

- Doc: `HttpRequestArgs::max_response_bytes` is capped at 2MB, not 2MiB.

## [0.2.0] - 2025-02-18

### Changed

- Added `aux` field in `SignWithSchnorrArgs`, introducing `SchnorrAux` and `Bip341` types.
- Fixed `NodeMetrics` which should have a field `num_block_failures_total`, not `num_blocks_failures_total`.

## [0.1.0] - 2023-01-22

### Added

- Initial release of the `ic-management-canister-types` library.
