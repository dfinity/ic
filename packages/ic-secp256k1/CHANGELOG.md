# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- Upgrade the `k256` dependency from `0.13` to `0.14`. The public API is unchanged.
- `k256` is used without its `std` and `precomputed-tables` features. In `k256` 0.14, `std` enables `getrandom` 0.4, which needs a randomness backend on `wasm32-unknown-unknown`, and `precomputed-tables` requires `std` or `critical-section`. Without `precomputed-tables`, multiplication by the generator uses no precomputed table unless another crate in the build enables the feature.
- `PrivateKey::generate_using_rng` draws 32 bytes from the RNG until they encode a valid secret key, as `k256::SecretKey::random` did, so the same RNG state still yields the same key.
- On `wasm32`, `k256` 0.14 uses 64-bit limbs: the `cpubits` crate, with which it picks its limb size, promotes `wasm32` to 64 bits, and Wasm has no 64x64→128-bit multiplication. In Wasm instructions, public-key decompression then costs 3.3x what it cost with `k256` 0.13, and key derivation and signature verification about 1.9x and 1.75x. Canisters can build with `--cfg cpubits="32"` (for example `RUSTFLAGS='--cfg cpubits="32"'`) to get 32-bit limbs, which brings these costs back to about those of `k256` 0.13. The cfg applies to every crate that uses `cpubits`: for example, `p256` 0.14 signs and verifies about 1.5x more slowly with it.

### Fixed

- `PublicKey::verify_bip340_signature` and `PublicKey::verify_bip341_signature` return `false` for signatures shorter than 32 bytes instead of panicking.
- ECDSA signing derives the RFC 6979 nonce from the digest reduced modulo the group order, as RFC 6979 specifies. This changes the signature only for digests whose value is at least the group order.

## [0.3.0] - 2025-10-10

### Added

- Add support for offline derivation of public keys using the test keys hardcoded in PocketIC,
  similar to the support for mainnet derivation added in 0.2.0

## Changed

- Use the `Principal` directly from `ic-principal` rather than the re-export from `candid` and remove `candid` as dependency.

## [0.2.0] - 2025-08-14

### Added

- Add `PublicKey::mainnet_key` which allows convenient access to the master public
  keys used for threshold ECDSA and threshold BIP341 Schnorr on the Internet Computer.
- Add `PublicKey::derive_mainnet_key` to derive public key offline, in the same way it is done by the respective management canister call (`ecdsa_public_key`, `schnorr_public_key`).

## [0.1.0] - 2025-02-08

Initial release.
