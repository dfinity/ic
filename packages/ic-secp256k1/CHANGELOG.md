# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## Changed

- Use the `Principal` directly from `ic-principal` rather than the re-export from `candid` and remove `candid` as dependency.

## [0.2.0] - 2025-08-14

### Added

- Add `PublicKey::mainnet_key` which allows convenient access to the master public
  keys used for threshold ECDSA and threshold BIP341 Schnorr on the Internet Computer.

## [0.1.0] - 2025-02-08

Initial release.
