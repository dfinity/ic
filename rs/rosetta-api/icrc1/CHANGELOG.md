# Changelog
All notable changes to the ICRC-Rosetta project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [1.2.7] - 2025-10-29
### Added
- Metrics for `rosetta_synched_block_height` and `rosetta_target_block_height` ([#6896](https://github.com/dfinity/ic/pull/6896))

### Changed
- Burn and mint transaction fees are taken into account ([#6620](https://github.com/dfinity/ic/pull/6620))

### Fixed
- Fix exponential backoff in case of an error ([#6734](https://github.com/dfinity/ic/pull/6734))

## [1.2.6] - 2025-08-11
### Changed
- Deprecate `network_type` parameter ([#6434](https://github.com/dfinity/ic/pull/6434))

## [1.2.5] - 2025-08-11
### Fixed
- Handle startup ledger errors gracefully ([#5884](https://github.com/dfinity/ic/pull/5884))

## [1.2.4] - 2025-07-07
### Added
- Allow retrieving the aggregate balance of a ICRC1 token account ([#5773](https://github.com/dfinity/ic/pull/5773))

## [1.2.3] - 2025-05-27
### Fixed
- Fixed fee collector balance calculation for transfers using fee_collector_block_index ([#5304](https://github.com/dfinity/ic/pull/5304))

## [1.2.2] - 2025-06-15
### Fixed
- Fixed timestamp overflow in blocks table for values exceeding i64::MAX ([#5249](https://github.com/dfinity/ic/pull/5249))
- Fixed watchdog for initial sync to avoid killing the synchronization process ([#5250](https://github.com/dfinity/ic/pull/5250))
- Improved synchronization progress logs to show progress in relation to the full chain size ([#5250](https://github.com/dfinity/ic/pull/5250))
- Fixed flaky test_deriving_gaps_from_storage test ([#5024](https://github.com/dfinity/ic/pull/5024))
- Increased transaction search timeout from 10s to 30s for system tests ([#4446](https://github.com/dfinity/ic/pull/4446))

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
