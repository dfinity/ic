# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add offline derivation for ECDSA keys over the secp256r1 curve, behind the new (default) `secp256r1` feature. It supports the mainnet keys `key_1` and `test_key_1` as well as the PocketIC keys.

### Changed

- Upgrade the `ic-management-canister-types` dependency from `0.5.0` to `0.11.0`. The re-exported types now come from that version.
- Upgrade the (optional) `ic-vetkeys` dependency from `0.6.0` to `0.7.0`.
- The `vetkeys` feature now also depends on `ic-cdk-management-canister`.

## [0.3.0] - 2026-02-04

### Changed

- Upgrade the (optional) `ic-ed25519` dependency from `0.5.0` to `0.6.0`.
- Upgrade the (optional) `ic-vetkeys` dependency from `0.5.0` to `0.6.0`.

## [0.2.0] - 2025-10-20

### Added

- Add support for offline derivation of public keys using the test keys hardcoded in PocketIC

## [0.1.0] - 2025-09-29

Initial release.
