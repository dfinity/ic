# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- Upgrade the `p256` dependency from `0.13` to `0.14`. The public API is unchanged.
- Upgrade the `sha2` dependency from `0.10` to `0.11` and the `hmac` dependency from `0.12` to `0.13`. The public API is unchanged.
- `KeyDecodingError::InvalidKeyEncoding` messages that come from `der`/`spki` (now 0.8) or `pkcs8` (now 0.11) are worded differently. For a key on another curve, the message names the curve OID found in the key instead of the expected one.
- `PrivateKey::generate_using_rng` draws 32 bytes from the RNG until they encode a valid secret key, as `p256::ecdsa::SigningKey::random` did, so the same RNG state still yields the same key, and `PrivateKey::generate_insecure_key_for_testing` the same key for the same seed.

### Fixed

- ECDSA signing derives the RFC 6979 nonce from the digest reduced modulo the group order, as RFC 6979 specifies. This changes the signature only for digests whose value is at least the group order (for SHA-256 digests, about one in 2^32).

## [0.3.0] - 2026-10-20

### Added

- Add `PublicKey::mainnet_key` returning the mainnet master public keys `key_1` and `test_key_1`, identified by the new `MasterPublicKeyId`
- Add `PublicKey::pocketic_key` returning the master public keys PocketIC uses for `key_1`, `test_key_1` and `dfx_test_key`, identified by the new `PocketIcMasterPublicKeyId`
- Add `PublicKey::derive_mainnet_key` and `PublicKey::derive_pocketic_key`, offline equivalents of the `ecdsa_public_key` management canister call, and re-export `ic_principal::Principal` as `CanisterId` for them

## [0.2.0] - 2026-02-11

## Added

- Add `Signature` type which can handle DER vs IEEE 1363 encoding
- Add support for signing and verifying signatures encoded as DER
- Add `PublicKey::deserialize_from_xy`
- Add `PublicKey::deserialize_canonical_der`
- Add FIPS 186 test data

## Changed

- This crate is now Rust Edition 2024
- Use `std::sync::LazyLock` instead of `lazy_static`
- Switch to using version 3 of the `pem` crate

## [0.1.0] - 2025-05-22

Initial release.
