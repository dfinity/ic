# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- `SubnetCoolingDown`

### Changed
- Bumped `strum` and `strum_macros` to v0.28. `RejectCode` and `ErrorCode` implement `IntoEnumIterator` of strum v0.28, so code that iterates over them through `strum::IntoEnumIterator` has to use strum v0.28 too. This is a breaking change.

# 0.2.0 - 2025-05-14

### Added
- `CanisterSnapshotImmutable`

## 0.1.0 - 2025-02-28

### Added

- Types `RejectCode`, `ErrorCode`, `UserError`
