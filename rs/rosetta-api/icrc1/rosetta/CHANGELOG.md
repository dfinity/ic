# Changelog
All notable changes to the ICRC-Rosetta project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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