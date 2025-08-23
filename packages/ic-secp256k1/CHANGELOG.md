# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-08-14

### Added

- Add `PublicKey::mainnet_key` which allows convenient access to the master public
  keys used for threshold ECDSA and threshold BIP341 Schnorr on the Internet Computer.
- Add `PublicKey::derive_mainnet_key` to derive public key offline, in the same way it is done by the respective management canister call (`ecdsa_public_key`, `schnorr_public_key`).

## [0.1.0] - 2025-02-08

Initial release.
