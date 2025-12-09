# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-12-10

## Changed

- This crate now depends on version 2.2 of `ed25519-dalek`, in order to make use of a newly added interface which simplifies this crate's support for hierarchical derivation.

## [0.4.0] - 2025-10-10

### Added

- Add support for offline derivation of public keys using the test keys hardcoded in PocketIC,
  similar to the support for mainnet derivation added in 0.3.0

## Changed

- Use the `Principal` directly from `ic-principal` rather than the re-export from `candid` and remove `candid` as dependency.

## [0.3.0] - 2025-08-14

### Added

- Add `PublicKey::mainnet_key` which allows convenient access to the master public
  keys used for threshold EdDSA on the Internet Computer.
- Add `PublicKey::derive_mainnet_key` to derive public key offline, in the same way it is done by the respective management canister call (`schnorr_public_key`).

## [0.2.0] - 2025-02-14

### Added

- Added a new feature `rand` which controls if `ic-ed25519` will depend on the `rand`
  crate. Key generation and batch verification are not supported if `rand` support is
  disabled. Disabling this feature is useful anytime a dependency on `rand` is not
  desirable, particularly when building for the `wasm32-unknown-unknown` target used for
  the Internet Computer, due to the fact that a dependency of `rand`, namely `getrandom`,
  refuses to compile for this target.

## [0.1.0] - 2025-02-08

Initial release.
