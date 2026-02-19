# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.1] - 2026-02-18

### Changed

- Bump alloy-* from 1.1.2 to 1.5.2 ([#551](https://github.com/dfinity/evm-rpc-canister/pull/551))

[3.1.1]: https://github.com/dfinity/evm-rpc-canister/compare/3.1.0..3.1.1

## [3.1.0] - 2025-11-24

### Changed

- Bump `ic-cdk` to v0.19.0 ([#518](https://github.com/dfinity/evm-rpc-canister/pull/518))
- Bump Rust to v1.91.0 and upgrade dependencies ([#529](https://github.com/dfinity/evm-rpc-canister/pull/529))

[3.1.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_types-v3.0.0..evm_rpc_types-v3.1.0

## [3.0.0] - 2025-10-20

### Added

- Add conversions between several types in this crate and the corresponding `alloy` types. These conversions are only available with the `alloy` feature ([#465](https://github.com/dfinity/evm-rpc-canister/pull/465), [#466](https://github.com/dfinity/evm-rpc-canister/pull/466), [#467](https://github.com/dfinity/evm-rpc-canister/pull/467), [#476](https://github.com/dfinity/evm-rpc-canister/pull/476)).
- **Breaking:** Add `root` and `cumulativeGasUsed` fields to `TransactionsReceipt` type ([#474](https://github.com/dfinity/evm-rpc-canister/pull/474)).

[3.0.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_types-v2.1.0..evm_rpc_types-v3.0.0

## [2.1.0] - 2025-09-12

### Added
* New field to `evm_rpc_types::Metrics` for `max_response_bytes` exceeded errors ([#463](https://github.com/dfinity/evm-rpc-canister/pull/463))

### Fixed
* Fix `MultiRpcResult::map` so non-injective mappings can turn `Inconsistent` results into `Consistent` ([#456](https://github.com/dfinity/evm-rpc-canister/pull/463))

[2.1.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_types-v2.0.0...evm_rpc_types-v2.1.0

## [2.0.0] - 2025-08-12

### Added

- Method `as_array()` on `Hex20`, `Hex32` and `Hex256` to return an immutable reference to the underlying array ([#432](https://github.com/dfinity/evm-rpc-canister/pull/432)).

### Changed

- The error variant `HttpOutcallError::IcError` now uses a local copy of `ic_cdk::api::call::RejectionCode`, renamed to `LegacyRejectionCode`. This was made to remove `ic-cdk` as a dependency. ([#428](https://github.com/dfinity/evm-rpc-canister/pull/428)).

### Removed

- Removed the types `RegexString` and `RegexSubstitution` to use the ones from the `canlog` crate ([#437](https://github.com/dfinity/evm-rpc-canister/pull/437)).

[2.0.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_types-v1.4.0...evm_rpc_types-v2.0.0

## 1.4.0 - 2025-06-04

### Added

- Customize maximum block range for `eth_getLogs` ([#424](https://github.com/dfinity/evm-rpc-canister/pull/424))

## 1.3.0 - 2025-02-11

### Added

- The number of nodes in a subnet can be specified in the installation arguments (new optional field `nodes_in_subnet` in `InstallArgs`).
- Allow to override provider URL upon installation for testing purposes (new optional field `override_provider` in `InstallArgs`)

## 1.2.0 - 2024-10-17

### Added

- v1.2.0 Added types to support `eth_call.`

### Fixed

- Added missing `serde::Deserialize` annotation on `Provider`, `RpcAccess` and `RpcAuth` structs.

## 1.1.0 - 2024-10-14

### Changed

- v1.1.0 Improve Debug and Display implementations for `HexByte`, `Hex20`, `Hex32`, `Hex256`, `Hex` and `Nat256`.
- v1.1.0 Improve Debug implementation of `RpcApi`.

## 1.0.0 - 2024-10-07

### Added

- v1.0.0 Move `InstallArgs` and associated types to this crate.
- v1.0.0 Move `Provider` and associated types to this crate.
- v1.0.0 `Nat256`: transparent wrapper around a `Nat` to guarantee that it fits in 256 bits.
- v1.0.0 `HexByte`, `Hex20`, `Hex32`, `Hex256` and `Hex` : Candid types wrapping an amount of bytes (`u8` for `HexByte`,
  `[u8; N]` for `HexN`, and `Vec<u8>` for `Hex`) that can be represented as an hexadecimal string (prefixed by `0x`)
  when serialized.
- v1.0.0 Move `Block` to this crate.
- v1.0.0 Move `BlockTag` to this crate.
- v1.0.0 Move `FeeHistoryArgs` and `FeeHistory` to this crate.
- v1.0.0 Move `GetLogsArgs` and `LogEntry` to this crate.
- v1.0.0 Move `GetTransactionCountArgs` to this crate.
- v1.0.0 Move `RpcConfig` to this crate.
- v1.0.0 Move `SendRawTransactionStatus` to this crate.
- v1.0.0 Move `TransactionReceipt` to this crate.
- v1.0.0 Move providers-related types `EthMainnetService`, `EthSepoliaService`, `HttpHeader`, `L2MainnetService`,
  `RpcApi`, `RpcConfig`, `RpcService`, `RpcServices` to this crate.
- v1.0.0 Move result-related types `HttpOutcallError`, `JsonRpcError`, `MultiRpcResult`, `ProviderError`, `RpcError`,
  `RpcResult`, `ValidationError` to this crate.
