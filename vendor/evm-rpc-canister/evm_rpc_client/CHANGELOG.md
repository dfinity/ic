# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-02-18

### Changed

- **BREAKING:** Bump `ic-canister-runtime` to v0.2.0. See PR description for more details on the breaking changes. 
  Notably, clients instances created with `EvmRpcClient::builder_for_ic()` now by default do **not** perform 
  inter-canister calls if the canister performing the calls is stopping. 
  To enable calls while the canister is stopping, the client can be initialized with a custom
  [`ic_canister_runtime::IcRuntime`](https://docs.rs/ic-canister-runtime/0.2.0/ic_canister_runtime/struct.IcRuntime.html)
  instance configured to allow such calls with the [`allow_calls_when_stopping`](https://docs.rs/ic-canister-runtime/0.2.0/ic_canister_runtime/struct.IcRuntime.html#method.allow_calls_when_stopping) method. ([#555](https://github.com/dfinity/evm-rpc-canister/pull/555))

[0.4.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_client-v0.3.0..evm_rpc_client-v0.4.0

## [0.3.0] - 2025-11-24

### Changed

- Bump `ic-cdk` to v0.19.0 ([#518](https://github.com/dfinity/evm-rpc-canister/pull/518))
- Bump Rust to v1.91.0 and upgrade dependencies ([#529](https://github.com/dfinity/evm-rpc-canister/pull/529))

[0.3.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_client-v0.2.0..evm_rpc_client-v0.3.0

## [0.2.0] - 2025-11-03

### Added

- Add `.request_cost()` method to `RequestBuilder` to compute the cycles cost of a request via the new `CyclesCost` query endpoints ([#509](https://github.com/dfinity/evm-rpc-canister/pull/509))
- Add the option to configure a retry strategy in the EVM RPC client to e.g., try a request with increasingly many cycles if it fails due to insufficient cycles ([#512](https://github.com/dfinity/evm-rpc-canister/pull/512))

[0.2.0]: https://github.com/dfinity/evm-rpc-canister/compare/evm_rpc_client-v0.1.0...evm_rpc_client-v0.2.0

## [0.1.0] - 2025-10-20

### Added

- Add methods to modify RPC config to `RequestBuilder` ([#494](https://github.com/dfinity/evm-rpc-canister/pull/494))
- Add `alloy` feature flag to `evm_rpc_client` ([#484](https://github.com/dfinity/evm-rpc-canister/pull/484))
- Add new `json_request` endpoint ([#477](https://github.com/dfinity/evm-rpc-canister/pull/477))
- Add client support for `eth_getTransactionReceipt` ([#476](https://github.com/dfinity/evm-rpc-canister/pull/476))
- Add `eth_sendRawTransaction` client support ([#467](https://github.com/dfinity/evm-rpc-canister/pull/467))
- Add client support for `eth_call` ([#466](https://github.com/dfinity/evm-rpc-canister/pull/466))
- Add client support for `eth_getTransactionCount` ([#465](https://github.com/dfinity/evm-rpc-canister/pull/465))
- Add support for `eth_feeHistory` to client ([#460](https://github.com/dfinity/evm-rpc-canister/pull/460))
- Add support for `eth_getBlockByNumber` to client ([#459](https://github.com/dfinity/evm-rpc-canister/pull/459))
- Add EVM RPC canister client ([#447](https://github.com/dfinity/evm-rpc-canister/pull/447))

[0.1.0]: https://github.com/dfinity/evm-rpc-canister/releases/tag/evm_rpc_client-v0.1.0