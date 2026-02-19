# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-02-17

### Added

- Middleware to prevent HTTPs outcalls when stopping ([#76](https://github.com/dfinity/canhttp/pull/76))

[0.5.1]: https://github.com/dfinity/canhttp/compare/canhttp-v0.5.0..canhttp-v0.5.1

## [0.5.0] - 2026-01-30

### Added

- Add support for batched JSON-RPC requests ([#65](https://github.com/dfinity/canhttp/pull/65))
- Add replicated request extension ([#70](https://github.com/dfinity/canhttp/pull/70))

### Changed

- Update dependencies ([#72](https://github.com/dfinity/canhttp/pull/72))

[0.5.0]: https://github.com/dfinity/canhttp/compare/canhttp-v0.4.0..canhttp-v0.5.0

## [0.4.0] - 2025-11-21

### Added

- Add `JsonRpcHttpLayer` which combines the `HttpConversionLayer`, `JsonConversionLayer` and `ConsistentJsonRpcIdFilter` middlewares into a single convenient-to-use layer ([#46](https://github.com/dfinity/canhttp/pull/46))
- Add example canisters demonstrating JSON-RPC functionalities and parallel calls ([#48](https://github.com/dfinity/canhttp/pull/48))

### Changed

- Bump `ic-cdk` to v0.19.0 ([#40](https://github.com/dfinity/canhttp/pull/40))

### Fixed

- Missing optional dependency on `serde` for `multi` feature ([#47](https://github.com/dfinity/canhttp/pull/47))

[0.4.0]: https://github.com/dfinity/canhttp/compare/canhttp-v0.3.0..canhttp-v0.4.0

## [0.3.0] - 2025-10-08

### Added
- **Breaking:** A new method `charge_cycles` that does the actual charging was added to `CyclesChargingPolicy` ([#7](https://github.com/dfinity/canhttp/pull/7))
- Example of canister using the library to make HTTP requests ([#6](https://github.com/dfinity/canhttp/pull/6))

### Changed
- **Breaking:** Update `ic-cdk` to `v0.18.7` including several changes to align with the new HTTP outcall API ([#21](https://github.com/dfinity/canhttp/pull/21)). Notably:
  - `IcError` is refactored into an enum
  - Use of the new `HttpRequestArgs` and `HttpRequestResult` types in `CyclesChargingPolicy` and `Client` trait impls
  - Removal of `IcHttpRequestWithCycles`, `CyclesCostEstimator`, `CyclesAccountingError` and `CyclesAccounting` due to the `ic-cdk` method for making HTTP outcalls now taking care of charging cycles

[0.3.0]: https://github.com/dfinity/canhttp/compare/canhttp-v0.2.1..canhttp-v0.3.0

## [0.2.1] - 2025-07-11

### Added

- An `iter` method to `canhttp::multi::MultiResults` returning a borrowing iterator.

### Changed
- The `canhttp` crate has been moved from the [`evm-rpc-canister`](https://github.com/dfinity/evm-rpc-canister) repository to the new [`canhttp`](https://github.com/dfinity/canhttp) repository.

[0.2.1]: https://github.com/dfinity/canhttp/compare/canhttp-v0.2.0..canhttp-v0.2.1

## [0.2.0] - 2025-07-08

### Added
- Data structures `TimedSizedVec<T>` and `TimedSizedMap<K, V>` to store a limited number of expiring elements ([#434](https://github.com/dfinity/evm-rpc-canister/pull/434))
- Method to list `Ok` results in a `MultiResults` ([#435](https://github.com/dfinity/evm-rpc-canister/pull/435))

### Changed

- **Breaking:** change the `code` field in the `IcError` type to use `ic_error_types::RejectCode` instead of `ic_cdk::api::call::RejectionCode` ([#428](https://github.com/dfinity/evm-rpc-canister/pull/428))

[0.2.0]: https://github.com/dfinity/canhttp/compare/canhttp-v0.1.0..canhttp-v0.2.0

## [0.1.0] - 2025-06-04

### Added

- JSON-RPC request ID with constant binary size ([#397](https://github.com/dfinity/evm-rpc-canister/pull/397))
- Use `canhttp` to make parallel calls ([#391](https://github.com/dfinity/evm-rpc-canister/pull/391))
- Improve validation of JSON-RPC requests and responses to adhere to the JSON-RPC specification ([#386](https://github.com/dfinity/evm-rpc-canister/pull/386) and [#387](https://github.com/dfinity/evm-rpc-canister/pull/387))
- Retry layer ([#378](https://github.com/dfinity/evm-rpc-canister/pull/378))
- JSON RPC conversion layer ([#375](https://github.com/dfinity/evm-rpc-canister/pull/375))
- HTTP conversion layer ([#374](https://github.com/dfinity/evm-rpc-canister/pull/374))
- Observability layer ([#370](https://github.com/dfinity/evm-rpc-canister/pull/370))
- Library `canhttp` ([#364](https://github.com/dfinity/evm-rpc-canister/pull/364))

[0.1.0]: https://github.com/dfinity/canhttp/releases/tag/canhttp-v0.1.0
