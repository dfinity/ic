# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [2.1.0] - 2024-08-21
### Fixes
- Enable store-location option to be set by a user
- Replacing internal crypto library `ic_canister_client_sender` with `ic_crypto_ed25519` 
  and `ic_crypto_ecdsa_secp256k1`.
- Return the correct `signature_type` in the `payloads` returned by the `construction_payloads` endpoint.
- Handle Errors that may occur while deserializing objects using serde_json
### Added
- /call endpoint with the method 'query_block_range' to fetch multiple blocks at once
### Changed
- [BREAKING CHANGE]: consolidate block and transaction tables into a single table
  The clients have to delete the old database and re-sync the Rosetta node from scratch. 

## [2.0.0] - 2024-01-18
### Fixes
- Prohibit Rosetta from spamming the ledger in case of errors at the ledger client. 
### Added
- Add `timestamp` to the `blocks` table
- Add support for `list_neurons`. Lets a user query a list of all the neurons a user has created.
- Add support for `list_known_neurons`. Lets a user query a list of all publicly known neurons.

## [1.9.0] - 2023-11-16
### Fixes
- Return transaction metadata (`memo` and `created_at_time`) in `/construction/parse`
- Remove `rosetta-exchanges.ic0.app`
### Added
- Add support for ICRC-2
- Add support for voting staking
- Add support for auto staking
- Add the ability to fetch pending proposals and proposal info
- Add listen to port file to rosetta
### Changed
- BREAKING CHANGE: update the database structure to support the ICRC-2 standard transactions.
  The clients have to delete the old database and re-sync the Rosetta node from scratch. 

## [1.8.0] - 2023-01-16
### Fixes
- Validate the tip of the chain when blocks are downloaded.
- Handle duplicate transaction hashes
### Added
- Rosetta supports the stake_maturity functionality
- Rosetta supports Secp256k1 keys
### Changed
- The boundary node of the default exchanges testnet that Rosetta connects now now only supports IPv6 instead of IPv4
- Changed the log destination of the blocks synchronizer. It now logs in the same file as the rosetta-api.
- Changed the in-memory transaction table to a persistent SQLite table.

## [1.7.2] - 2022-10-18
### Fixed
- Invalid Docker image configuration.

### Changed
- The dfinity/rosetta-api docker image is now based on a
  [distroless](https://github.com/GoogleContainerTools/distroless)
  container that contains only the rosetta binary and direct runtime dependencies.
  As a consequence, you will not be able to enter shell on this image.

## [1.7.1] - 2022-10-12
### Fixed
- A bug in absence proof check, see
  https://github.com/dfinity/ic/commit/028b97f15783140dac7902b1a3b1b97a8196409c.

## [1.7.0] - 2022-09-20
### Fixed
- The Rosetta node can now correctly handle absence proofs
  (see https://internetcomputer.org/docs/current/references/ic-interface-spec/#example).
  All Rosetta node operators are advised to update to this release.

## [1.6.1] - 2022-08-26
### Added
- `blockchain` command line flag that overrides the blockchain name in the network identifier.
### Changed
- `NEURON_INFO` restricted data now contains followees and hotkeys.
- `log_config.yml` now contains a specific appender for the ledger blocks synchronizer.

## [1.6.0] - 2022-05-30
### Fixed
- Allow delegations when checking canister certificates.
  This enables certificate validation for custom ledgers.

### Changed
- Controller format (principal or public key) for Spawn operation.

## [1.5.1] - 2022-04-29
### Fixed
- Issue with FOLLOW and NEURON_INFO operations while using hotkeys.

### Changed
- Controller format (principal or public key) now explicit in operations used with a hotkey.

## [1.5.0] - 2022-04-06
### Added
- Support for `NEURON_INFO` operation.
- Support for `REMOVE_HOTKEY` operation.
- Support for `FOLLOW` operation.

## [1.4.0] - 2022-03-14
### Added
- Support for `MERGE_MATURITY` neuron management operation.
- Optional parameter `percentage_to_spawn` to allow partial spawning of neuron maturity with the existing `SPAWN` operation.

### Changed
- --token-name parameter renamed to --token-symbol

### Fixed
- /network/options always returns the full list of supported operations.
- Names of some neurons management operations changed to match the documentation:
  * `START_DISSOLVE` -> `START_DISSOLVING`
  * `STOP_DISSOLVE` -> `STOP_DISSOLVING`
  * `ADD_HOT_KEY` -> `ADD_HOTKEY`
- The output of /construction/submit endpoint now returns operation statuses in the metadata field as stated in the documentation.

## [1.3.0] - 2021-12-28
### Added
- /account/balance endpoint can now return information about neurons.
- Support for custom token names.
  Use -t command line argument to specify token name other than ICP.
- Support for `SPAWN` neuron management operation.

## [1.2.0] - 2021-09-28
### Added
- Support for `ADD_HOTKEY` neuron management operation.

### Changed
- Neuron address derivation is now supported by /construction/derive endpoint.
  Custom /neuron/derive endpoint is removed.
- /construction/submit endpoint now returns the list of operation statuses in metadata as described in the documentation.
  If there was a TRANSACTION operation in the list, the submit result will contain the hash of the corresponding ledger transfer.
  Otherwise, if all the actions are neuron-management actions, the transaction hash is all zero hash.
- "sqlite" is the default storage type now.
  Other storage types are deprecated.
- Block synchronization speed is significantly improved (~10x).
- /transaction/search endpoint now supports returning multiple transactions if the search criteria is empty.
  This enables clients to display the list of recent transactions in an efficient way.

## [1.1.0] - 2021-08-04
### Added
- Documentation for fund staking and neuron management (see `rosetta-api/docs`).
- Support for neuron management operations:
  * `SET_DISSOLVE_TIMESTAMP`
  * `START_DISSOLVING`
  * `STOP_DISSOLVING`

### Changed
- Neuron address is now supposed to be derived using a custom `/neuron/derive` endpoint.
  This is a temporary experimental feature, the next release won't contain this endpoint.

## [1.0.5] - 2021-07-22
### Added
- Support for fund staking (`STAKE` operation).
- Support for neuron address derivation.
- Sqlite storage backend.

### Changed
- BREAKING CHANGE: the internal encoding of transactions changed to support multi-step transactions (e.g., fund staking).
  Any transactions constructed with earlier versions of rosetta node cannot be applied by this version.


## [1.0.2] - 2020-12-10
### Added
- Original release.
