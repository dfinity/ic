Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-06-23

### Changed

- Make `RegexString` and `RegexSubstitution` types public.

## [0.1.0] - 2025-04-29

### Added

- Initial release of `canlog` crate.
- Wraps `ic_canister_log` to provide a more ergonomic logging interface with native support for log priority levels.
- `log!` macro to emit structured log messages associated with enum-based priority levels.
- Support for custom log priority levels via the `LogPriorityLevels` trait.
- Procedural macro `#[derive(LogPriorityLevels)]` (enabled with the `derive` feature) for automatic trait implementations.
- Filtering of log entries via the `GetLogFilter` trait and `LogFilter` enum.
- Regex-based filtering and substitution utilities via `RegexString` and `RegexSubstitution`.
- Sorting of logs using `Sort::{Ascending, Descending}`.
- `LogEntry` and `Log` types for capturing and serializing structured logs.
