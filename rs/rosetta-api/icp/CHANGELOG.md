# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## Unreleased

### Added
- Added support for legacy `SignedTransaction` format from pre-v2.1.0 for the `construction/submit` endpoint.

## [2.1.8] - 2025-10-09
### Added
- Added explicit timeout in ic-agent initialization to improve initial sync performance ([#7131](https://github.com/dfinity/ic/pull/7131))

## [2.1.7] - 2025-08-12
### Added
- Environment presets to configure ICP Rosetta API with `--environment` flag ([#5982](https://github.com/dfinity/ic/pull/5982))
- New endpoint `get_minimum_dissolve_delay` to retrieve the minimum dissolve delay of a neuron that allows voting ([#5863](https://github.com/dfinity/ic/pull/5863))
- Support for `DISBURSE_MATURITY` neuron operation. Allows to disburse neuron's maturity directly to an account ([#5994](https://github.com/dfinity/ic/pull/5994))

### Changed
- Grouped Rosetta CLI parameters for better organization and readability ([#5981](https://github.com/dfinity/ic/pull/5981))
- Ignore spender account in transfers when searching transactions by account ([#5794](https://github.com/dfinity/ic/pull/5794))

### Removed
- Removed deprecated `MERGE_MATURITY` neuron management operation.

## [2.1.6] - 2025-06-27
### Added
- Enhanced transaction search capabilities with database indexing optimizations for improved performance ([#5739](https://github.com/dfinity/ic/pull/5739))
- Extended search_transactions method in Rosetta client to support filtering by transaction_hash and operation_type ([#5739](https://github.com/dfinity/ic/pull/5739))
- Optional CLI flag --optimize-search-indexes to enable database indexing optimizations for transaction search ([#5739](https://github.com/dfinity/ic/pull/5739))

### Changed
- Enhanced test framework to support transfer_from transactions in valid_transactions_strategy ([#5592](https://github.com/dfinity/ic/pull/5592))
- Marked ICP Rosetta system tests as flaky to address test stability issues ([#5746](https://github.com/dfinity/ic/pull/5746))

## [2.1.5] - 2025-06-13
### Fixed
- Fixed heartbeat during initial sync to prevent premature watchdog timeouts ([#5293](https://github.com/dfinity/ic/pull/5293))
- Fixed integer overflow for balances when storing values higher than INT64_MAX ([#5401](https://github.com/dfinity/ic/pull/5401))

## [2.1.4] - 2025-05-10
### Added
- Token-specific metrics for better monitoring in multi-token environments ([#4790](https://github.com/dfinity/ic/pull/4790))
- New PocketIC Time type for improved testing ([#4864](https://github.com/dfinity/ic/pull/4864))

### Changed
- Replaced imports from ic_canisters_http_types to new ic_http_types crate ([#4866](https://github.com/dfinity/ic/pull/4866))
- Increased the sync thread watchdog timeout from 10 to 60 seconds to better handle IC instability ([#4863](https://github.com/dfinity/ic/pull/4863))
- Refactored and augmented Rosetta ICP metrics for better observability ([#3642](https://github.com/dfinity/ic/pull/3642))
- Migrated from dfn to cdk architecture ([#4436](https://github.com/dfinity/ic/pull/4436))

### Fixed
- Write ICP Rosetta port file atomically to fix flaky test issues ([#4760](https://github.com/dfinity/ic/pull/4760))
- Removed canister client library dependency for better architecture ([#4530](https://github.com/dfinity/ic/pull/4530))

## [2.1.3] - 2025-03-12
### Fixes
- Potential source of deadlock when accessing the database client. [#4147](https://github.com/dfinity/ic/pull/4147)
- Added retries when fetching the tip block. [#4301](https://github.com/dfinity/ic/pull/4301)
- Added a watchdog thread to restart the sync thread when it's stale. [#4317](https://github.com/dfinity/ic/pull/4317)

### Added
- Additional error logs for when requests fail with an `InternalError`. [#4338](https://github.com/dfinity/ic/pull/4338)

## [2.1.2] - 2025-02-21
### Fixes
- fixed refresh voting power request so now the neuron controller can be specified.

## [2.1.1] - 2024-12-13
### Added
- added functionality to refresh voting power on the governance canister

## [2.1.0] - 2024-08-21
### Fixes
- Enable store-location option to be set by a user
- Replacing internal crypto library `ic_canister_client_sender` with `ic_crypto_ed25519` 
  and `ic_crypto_ecdsa_secp256k1`.
- Return the correct `signature_type` in the `payloads` returned by the `construction_payloads` endpoint.
- Handle Errors that may occur while deserializing objects using serde_json
### Added
- /call endpoint with the method 'query_block_range' to fetch multiple blocks at once
- added functionality to refresh voting power on the governance canister
### Changed
- [BREAKING CHANGE]: consolidate block and transaction tables into a single table
  The clients have to delete the old database and re-sync the Rosetta node from scratch.
- [BREAKING CHANGE]: change `pub type SignedTransaction = Vec<Request>` to
  `pub struct SignedTransaction { pub requests: Vec<Request> }`, affecting the
  `construction/submit` endpoint.

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
