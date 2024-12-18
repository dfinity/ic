# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-08-20

### Added

- Upgrade ic-verify-bls-signature from 0.2 to 0.6.
- Use ic-verify-bls-signature without the `rand` feature. This allows for compilation to WASM.
- Point documentation to docs.rs.

## [0.1.0] - 2024-07-24

### Added

- Package setup
- `verify_canister_sig()`-function with basic tests.
