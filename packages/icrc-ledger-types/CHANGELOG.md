# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add ICRC-107 fee collector transaction type.

## 0.1.12

### Added

- `try_from_subaccount_to_principal` that returns an error rather than panicking if the subaccount is not a valid Principal.
- Add optional fee to `Mint` and `Burn` icrc3 operations.

## 0.1.11

### Changed
- Fix the generic ICRC-21 message to conform to https://github.com/dfinity/wg-identity-authentication/tree/main/topics/ICRC-21/examples, add FieldsDisplay and remove LineDisplay.

## 0.1.10

### Changed

- Remove unneeded dependency on `ic-cdk`.

## 0.1.9

### Added

- `icrc103` types.

## 0.1.8

### Added

- Add default encoding and decoding of a Principal in a Subaccount.

## 0.1.7

### Added

- Rustdoc.

## 0.1.6

### Added

- `icrc3` and `icrc21` types.

## 0.1.5

- Use candid 0.10

## 0.1.4

- Types derive `serde::Serialize`.

## 0.1.3

- Add `icrc3` module.

## 0.1.2

- Change ICRC-1 Account to use the standard ICRC-1 Textual Representation.

## 0.1.1

## 0.1.0

### Added

- `icrc1` and `icrc2` types.
- The `Value` type and the algorithm to compute its hash.

### Changed

- Updated candid library to the latest version.
