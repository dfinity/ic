# Changelog

All notable changes to the project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [1.0.1] - 2025-09-11

### Added

- Added `env_var_*` API.

## [1.0.0] - 2025-06-25

### Changed

- Introduced new safe API in the crate root. The raw C bindings have been moved to `ic0::sys`.

### Migration guide

- Replace `ic0::*` with `ic0::sys::*`, e.g., `ic0::msg_arg_data_size()` -> `ic0::sys::msg_arg_data_size()`.

## [0.25.1] - 2025-06-04

Changelog introduced
