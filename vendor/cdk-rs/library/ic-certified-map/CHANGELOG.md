# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.4.1] - 2025-09-05

### Added
- Implement `CandidType`, `Serialize`, and `Deserialize` for the `RbTree`.
- Implement `Deserialize` for the `HashTree`.

## [0.4.0] - 2023-07-13

### Changed
- Upgrade `ic-cdk` to v0.10 and `candid` to v0.9.

## [0.3.4] - 2023-03-01
### Added
- Derive common traits for structs.

## [0.3.3] - 2023-02-22
### Fixed
- Update links in doc.

## [0.3.2] - 2022-11-10
### Changed
- Make `RbTree::new` and `RbTree::is_empty` both `const`.

## [0.3.1] - 2022-09-16
### Changed
- Updated `sha2` dependency.

## [0.3.0] - 2022-01-13
### Added
- `RbTree::iter()` method.
- impls of `Clone`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `FromIterator`, and `Debug` for `RbTree`.

## [0.2.0] - 2021-09-16
### Added
- `RbTree::value_range()` method to get a witness for a range of keys with values.

### Changed
- RbTree::key_range() method returns tighter key bounds which reduces the size of witnesses.
- Updated the version of candid from `0.6.19` to `0.7.1` ([#72](https://github.com/dfinity/cdk-rs/pull/72)).
- Hash tree leaves can now hold both references and values ([#121](https://github.com/dfinity/cdk-rs/issues/121)).
  This is a BREAKING CHANGE, some clients might need to slightly change and recompile their code.

## [0.1.0] - 2021-05-04
### Added
* Initial release of the library.
