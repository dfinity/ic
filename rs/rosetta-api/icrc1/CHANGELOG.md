# Changelog
All notable changes to the ICRC-Rosetta project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [1.2.1] - 2025-05-10
### Added
- Token-specific metrics for multi-token instances - metrics now include token labels to help distinguish between different tokens ([#4790](https://github.com/dfinity/ic/pull/4790)).

### Changed
- Increased the sync thread watchdog timeout from 10 to 60 seconds to better handle IC instability cases ([#4863](https://github.com/dfinity/ic/pull/4863)).
- Added more resources for icrc_multitoken_rosetta_system tests to address flakiness ([#4741](https://github.com/dfinity/ic/pull/4741)).
- Always return ICRC-3 compliant certificate for consistency ([#4504](https://github.com/dfinity/ic/pull/4504)).

## [1.2.0] - 2025-04-04
### Added
- Support for multiple tokens within a single instance.

## Fixed
- Removed unnecessary recurrent block table scans to identify gaps -> sharp drop in I/O operations.


## [1.1.2] - 2024-11-21
### Fixed
- Support for icrc3 certificates

## [1.1.1] - 2024-07-09
### Added
- Added /ready endpoint which indicates whether Rosetta is finished with its initial block synch
- /call endpoint with the method 'query_block_range' to fetch multiple blocks at once
### Fixes
- Changed default database path to match /data/db.sqlite

## [1.1.0] - 2024-06-13
### Fixes
- Make search/transactions a custom SQL query for latency improvement
- Remove block count for faster /block response
### Added
- Tx hash indexer on blocks table
- Block hash indexer on blocks table
- Use spawn_blocking for blocking threads in a tokio environment
- Enable store-file option to be set by a user
### Added
- Tx hash indexer on blocks table
### Changed
- Add log to console output
- Separate read and write access between rosetta server and block synchronizer

## [1.0.2] - 2024-05-08
### Fixes
- Replacing internal crypto library `ic_canister_client_sender` with `ic_crypto_ed25519` 
  and `ic_crypto_ecdsa_secp256k1`.
### Changed
- `/block` endpoint is changed to return the latest block if no index or hash is provided.

## [1.0.0] - 2024-03-26
### Added
- Original release.