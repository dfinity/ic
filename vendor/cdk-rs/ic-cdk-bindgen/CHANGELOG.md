# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.2.0] - 2026-02-19

### New API Design

The `ic-cdk-bindgen` crate introduces a completely redesigned API to integrate seamlessly with `ic-cdk` v0.18 and later:
- The new API centers around the `Config` struct, requiring explicit specification of canister name and candid path.
- The bindgen now supports two modes:
  - `static_callee`: The canister ID is known at compile time.
  - `dynamic_callee`: The canister ID will be fetched via ICP environment variables at runtime.
- The "Type Selector" config can be set to customize how Candid types are translated to Rust types.
- Removed implicit handling of `dfx` environment variables. See the "Use with `dfx`" section in the crate documentation for more info.

## [0.1.3] - 2024-02-27

### Added

- Resolve CANISTER_CANDID_PATH and CANISTER_ID from standardized environment variables (uppercase canister names). (#467)
  - The support for legacy (non-uppercase) env vars is kept.
  - It will be removed in next major release (v0.2).

## [0.1.2] - 2023-11-23

### Changed

- Change `candid` dependency to the new `candid_parser` library. (#448)
  More details here: https://github.com/dfinity/candid/blob/master/Changelog.md#2023-11-16-rust-0100

## [0.1.1] - 2023-09-18

### Changed

- Update `candid` dependency to 0.9.6 which change the Rust bindings. (#424)

## [0.1.0] - 2023-07-13

### Added

- First release. (#416)
