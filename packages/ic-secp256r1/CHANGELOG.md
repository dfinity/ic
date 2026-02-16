# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-11

## Added

- Add `Signature` type which can handle DER vs IEEE 1363 encoding
- Add support for signing and verifying signatures encoded as DER
- Add `PublicKey::deserialize_from_xy`
- Add `PublicKey::deserialize_canonical_der`
- Add FIPS 186 test data

## Changed

- This crate is now Rust Edition 2024
- Use `std::sync::LazyLock` instead of `lazy_static`
- Switch to using version 3 of the `pem` crate

## [0.1.0] - 2025-05-22

Initial release.
