# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.16.0] - 2025-11-12

### Changed

- Upgrade `ic-cdk` to v0.19.

## [0.15.0] - 2025-04-22

### Changed

- Upgrade `ic-cdk` to v0.18.

## [0.14.0] - 2024-11-08

### Changed

- Upgrade `ic-cdk` to v0.17.

### Added
- as_bytes method to AccountIdentifier in ic-ledger-types

## [0.13.0] - 2024-08-27

### Changed

- Upgrade `ic-cdk` to v0.16.

## [0.12.0] - 2024-07-01

### Changed

- Upgrade `ic-cdk` to v0.15.

## [0.11.0] - 2024-05-17

### Changed

- Upgrade `ic-cdk` to v0.14.

## [0.10.0] - 2024-03-01

### Changed
- Upgrade `ic-cdk` to v0.13.

## [0.9.0] - 2023-11-23

### Changed
- Upgrade `ic-cdk` to v0.12 and `candid` to v0.10.

## [0.8.0] - 2023-09-18

### Changed
- Upgrade `ic-cdk` to v0.11.

## [0.7.0] - 2023-07-13

### Added
- from_hex/from_slice/to_hex methods to AccountIdentifier in ic-ledger-types

### Changed
- Upgrade `ic-cdk` to v0.10 and `candid` to v0.9.

## [0.6.0] - 2023-06-20
### Changed
- Upgrade `ic-cdk` to v0.9.

## [0.5.0] - 2023-05-26
### Changed
- Upgrade `ic-cdk` to v0.8.

## [0.4.2] - 2023-03-01
### Fixed
- Fill missing docs.

## [0.4.1] - 2023-02-22
### Fixed
- Use automatic link in document.

## [0.4.0] - 2023-02-13
### Changed
- Extend the Operation type to support approve/transfer_from transactions.

## [0.3.0] - 2023-02-03
### Changed
- Upgrade `ic-cdk` to v0.7.

## [0.2.1] - 2023-01-20

### Added

- Implemented `From<Principal>` for `Subaccount` (#361)

## [0.2.0] - 2022-11-04
### Changed
- Upgrade `ic-cdk` to v0.6 and `candid` to v0.8.

## [0.1.2] - 2022-05-31
### Added
- Integrate with the ledger's `token_symbol` method
- Methods to query ledger blocks.

### Changed
- Support conversion from `[u8; 32]` to `AccountIdentifier` via `TryFrom` with CRC-32 check.
- Upgrade `ic-cdk` to 0.5.0

## [0.1.1] - 2022-02-04
### Changed
- Upgrade `ic-cdk` to v0.4.0.

## [0.1.0] - 2021-11-11
### Added
- Initial release of the library.
