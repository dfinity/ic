# Changelog
All notable changes to the ICRC-Rosetta project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Fixes
### Added
### Changed

## [1.0.2] - 2024-05-08
### Fixes
- Replacing internal crypto library `ic_canister_client_sender` with `ic_crypto_ed25519` 
  and `ic_crypto_ecdsa_secp256k1`.
### Changed
- `/block` endpoint is changed to return the latest block if no index or hash is provided.

## [1.0.0] - 2024-03-26
### Added
- Original release.