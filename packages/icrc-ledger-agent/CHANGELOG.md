# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Bump ic-agent dependency to v0.50.0. This is a breaking change: `Icrc1Agent::agent` and
  `Icrc1AgentError::AgentError` now hold ic-agent 0.50 types, so callers must pass an
  ic-agent 0.50 `Agent`.

## 0.2.0

### Changed
- Bump icrc-ledger-types dependency to v0.2.0.

## 0.1.1

### Changed

- Bump icrc-ledger-types dependency to v0.1.10.
- Also support leb128 encoded last_block_hash icrc3 certificates

### Added

- The basic functions for interacting with icrc ledgers.
