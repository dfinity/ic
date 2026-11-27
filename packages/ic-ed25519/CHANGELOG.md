# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- Upgrade the `ed25519-dalek` dependency from version 2 to 3, `curve25519-dalek` from 4 to 5 and `hkdf` from 0.12 to 0.13. The public API is unchanged, and key generation, signing, key serialization and signature verification produce the same results as before.
- `PrivateKey::generate_using_rng` takes the next 32 bytes of the RNG output as the key, as `ed25519-dalek` 2 did, so the same RNG state still yields the same key.
- The details of `PrivateKeyDecodingError::InvalidKeyEncoding` and `PublicKeyDecodingError::InvalidKeyEncoding` for malformed DER input are worded differently, as they come from `der` 0.8, `spki` 0.8 and `pkcs8` 0.11.
- Upgrade the `rand` dependency from version 0.8 to 0.10 and `rand_chacha` from 0.3 to 0.10. `PrivateKey::generate_using_rng` and `PublicKey::batch_verify` now take an RNG implementing `rand::CryptoRng` from `rand` 0.10 (`rand_core` 0.10). The same RNG output gives the same keys as before.
- `PrivateKey::generate` is no longer available on `wasm32-unknown-unknown`. Use `PrivateKey::generate_using_rng` or `PrivateKey::generate_from_seed` there.

## [0.6.0] - 2026-02-04

## Added

- Added `PublicKey::convert_raw32_to_der` which is an infalliable variant of `PublicKey::convert_raw_to_der`

## Changed

- Use the more efficient Edwards conversion mentioned in 0.5.0 (from `ed25519-dalek` v2.2) also for public key derivation (`PublicKey::derive_subkey` and `PublicKey::derive_subkey_with_chain_code`). So far, the more efficient conversion was only used in `PublicKey::new`.

## [0.5.0] - 2025-12-09

## Changed

- This crate now depends on version 2.2 of `ed25519-dalek`, in order to make use of a newly added interface which simplifies this crate's support for hierarchical derivation.
- Update dependency on `pem` crate from crate major version 1 to major version 3.
- Implement `Eq` and `PartialEq` traits for `SignatureError`.

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
