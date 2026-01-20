# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-12-08

### Changed

- Bump `pocket-ic` to v11.0.0

## [0.2.0] - 2025-11-24

### Changed

- Bump `pocket-ic` to v10.0.0

## [0.1.1] - 2025-06-17

### Changed

- Expanded `README.md` with detailed crate description and feature overview.
- Expanded `CHANGELOG.md` entry for v0.1.0.

## [0.1.0] - 2025-06-17

### Added

- Initial release of the crate providing fluent assertions for metrics in Rust, designed for use with Internet Computer (IC) canisters.
- Core struct `MetricsAssert<T>` enabling Regex-based test assertions using:
    - `.assert_contains_metric_matching(...)`
    - `.assert_does_not_contain_metric_matching(...)`
- Support for both synchronous and asynchronous querying of canister metrics via:
    - `CanisterHttpQuery` (trait for sync HTTP querying)
    - `AsyncCanisterHttpQuery` (trait for async HTTP querying)
- `MetricsAssert::from_http_query(...)` and `from_async_http_query(...)` constructors to retrieve metrics from the `/metrics` endpoint and assert on their contents.
- Optional **`pocket_ic` feature**:
    - Adds support for integration testing with [`PocketIc`](https://docs.rs/pocket-ic).
    - Provides implementations of `CanisterHttpQuery` and `AsyncCanisterHttpQuery` for types that implement:
        - `PocketIcHttpQuery` (trait for sync HTTP querying using `PocketIc`)
        - `PocketIcAsyncHttpQuery` (trait for async HTTP querying using `PocketIc`)
