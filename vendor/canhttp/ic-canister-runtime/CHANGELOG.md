# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-17

### Added

- Support for `StubRuntime` returning `IcError` ([#81](https://github.com/dfinity/canhttp/pull/81))
- `Clone` implementation for `StubRuntime` ([#79](https://github.com/dfinity/canhttp/pull/79))

### Changed

- Change the default behavior to prevent inter-canister calls when the canister is stopping ([#78](https://github.com/dfinity/canhttp/pull/78))

[0.2.0]: https://github.com/dfinity/canhttp/compare/ic-canister-runtime-v0.1.2..ic-canister-runtime-v0.2.0

## [0.1.2] - 2026-01-30

### Changed

- Update dependencies ([#72](https://github.com/dfinity/canhttp/pull/72))

[0.1.2]: https://github.com/dfinity/canhttp/compare/ic-canister-runtime-v0.1.1..ic-canister-runtime-v0.1.2

## [0.1.1] - 2025-12-09

### Fixed

- Point to correct READMEs ([#60](https://github.com/dfinity/canhttp/pull/60))

[0.1.1]: https://github.com/dfinity/canhttp/compare/ic-canister-runtime-v0.1.0..ic-canister-runtime-v0.1.1

## [0.1.0] - 2025-11-21

### Added

- Add helper methods to `CyclesWalletRuntime` ([#44](https://github.com/dfinity/canhttp/pull/44))
- Add READMEs and examples ([#42](https://github.com/dfinity/canhttp/pull/42))
- Add `StubRuntime` ([#41](https://github.com/dfinity/canhttp/pull/41))
- Add `CyclesWalletRuntime` ([#37](https://github.com/dfinity/canhttp/pull/37))
- Add `Runtime` crate and `IcRuntime` implementation ([#35](https://github.com/dfinity/canhttp/pull/35))

[0.1.0]: https://github.com/dfinity/canhttp/releases/tag/ic-canister-runtime-v0.1.0
