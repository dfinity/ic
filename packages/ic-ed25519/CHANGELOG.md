# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-02-14

### Added

- Added a new feature `rand` which controls if `ic-ed25519` will depend on the `rand`
  crate. Key generation and batch verification are not supported if `rand` support is
  disabled. Disabling this feature is useful anytime a dependency on `rand` is not
  desirable, particularly when building for the `wasm32-unknown-unknown` target used for
  the Internet Computer, due to the fact that a dependency of `rand`, namely `getrandom`,
  refuses to compile for this target.

## [0.1.0] - 2025-02-07

Initial release.
