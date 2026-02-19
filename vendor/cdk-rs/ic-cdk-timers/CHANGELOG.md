# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [1.0.0] - 2025-11-13

- `ic-cdk-timers` no longer has a dependency on `ic-cdk` and no longer needs to be upgraded when `ic-cdk` is upgraded.
- Breaking: Timer body function signatures have been updated which eliminating the need for explicit `spawn` calls within timer callbacks. 
  - `set_timer`: now takes `impl Future<Output = ()>`. `|| {}` should be changed to `async {}`,
  - `set_timer_interval`: now takes `FnMut() -> impl Future`. `|| {}` should be changed to `|| async {}`.
  - `set_timer_interval_serial`: new function, takes `AsyncFnMut()`.
  - If you have any immediate `spawn` calls, you can remove them and run the async code directly. (You do not have to.)

## [0.12.2] - 2025-06-25

- Upgrade `ic0` to v1.0.

## [0.12.1] - 2025-06-17

- Upgrade `ic0` to v0.25.

## [0.12.0] - 2025-04-22

- Upgrade `ic-cdk` to v0.18.

## [0.11.0] - 2024-11-04

### Changed

- Upgrade `ic-cdk` to v0.17.

## [0.10.0] - 2024-08-27

### Changed

- Upgrade `ic-cdk` to v0.16.

## [0.9.0] - 2024-07-01

### Changed

- Upgrade `ic-cdk` to v0.15.

## [0.8.0] - 2024-05-17

### Changed

- Upgrade `ic-cdk` to v0.14.

## [0.7.0] - 2024-03-01

### Changed

- Upgrade `ic-cdk` to v0.13.

## [0.6.0] - 2023-11-23

### Changed

- Upgrade `ic-cdk` to v0.12.

## [0.5.0] - 2023-09-18

### Changed

- Upgrade `ic-cdk` to v0.11.

## [0.4.0] - 2023-07-13

### Changed

- Upgrade `ic-cdk` to v0.10.

## [0.3.0] - 2023-06-20

### Changed

- Upgrade `ic-cdk` to v0.9.

## [0.2.0] - 2023-05-26

### Changed

- Upgrade `ic-cdk` to v0.8.

## [0.1.2] - 2023-03-01

## [0.1.1] - 2023-02-22

### Fixed

- Broken references to `ic_cdk::api::time`.

## [0.1.0] - 2023-02-03

### Added

- Initial release of the `ic-cdk-timers` library.
