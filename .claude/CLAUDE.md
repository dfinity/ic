# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# General

All commands should be run from the repository root (`/ic`).

## Repository Overview

This is the DFINITY Internet Computer Protocol (ICP) monorepo. The IC is a blockchain that runs smart contracts called **canisters** (WebAssembly modules). The primary implementation is in Rust under `rs/`.

Key top-level directories:
- `rs/` — All Rust source code (replica, canisters, libraries, tests)
- `ic-os/` — Operating system images: SetupOS, HostOS, GuestOS (the replica runs inside GuestOS)
- `packages/` — Standalone Rust crates publishable to crates.io
- `ci/` — CI scripts and the dev container (`ci/container/container-run.sh`)
- `cpp/` — C++ code (limited use)

## Key `rs/` Subsystems

- `rs/replica/` — The main replica binary (entry point for the IC node process)
- `rs/consensus/` — Consensus protocol implementation (block making, finalization, DKG, threshold ECDSA)
- `rs/execution_environment/` — Canister execution (hypervisor, Wasm execution, system calls)
- `rs/state_manager/` — Replicated state management and certification
- `rs/crypto/` — Cryptographic primitives and threshold signature schemes
- `rs/nns/` — Network Nervous System canisters (governance, registry, ledger, CMC)
- `rs/sns/` — Service Nervous System (tokenized DAOs)
- `rs/registry/` — Registry canister and client
- `rs/messaging/` — Cross-subnet messaging (XNet)
- `rs/http_endpoints/` — Public API HTTP endpoints
- `rs/orchestrator/` — Node orchestration (manages replica and GuestOS upgrades)
- `rs/tests/` — System/integration tests (require DFINITY infrastructure; do not run externally)
- `rs/pocket_ic_server/` — PocketIC: lightweight IC replica for testing canisters locally

## Dev Container

Building IC-OS images and running full system tests requires the dev container:
```
./ci/container/container-run.sh
```

## Build System

Bazel is the primary build system. Cargo/rustc is also available for Rust-only workflows.

Run all unit/integration tests (skip system tests):
```
bazel test //... --test_tag_filters=-system_test
```

Run a specific bazel test target:
```
bazel test //rs/consensus/... --test_output=errors
bazel test //rs/execution_environment:execution_environment_test --test_output=errors
```

Build a specific target:
```
bazel build //rs/replica:replica
```

Build IC-OS images:
```
bazel build //ic-os/guestos/envs/dev/...
```

## Clippy Rules of Note

The `clippy.toml` enforces several project-specific constraints:
- Prefer bounded channels over unbounded (`tokio::sync::mpsc::unbounded_channel`, `crossbeam::channel::unbounded`, etc. are disallowed)
- Prefer `std::sync::Mutex` over `tokio::sync::Mutex` unless `.await` is needed inside the lock
- Use `Write::write_all()` instead of `Write::write()`
- `bincode::deserialize_from` is banned (unsafe on untrusted data)

# Rust

After changing Rust code (`*.rs`) follow these steps in order:

1. **Format** by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   rustfmt <MODIFIED_RUST_FILES>
   ```
   where `<MODIFIED_RUST_FILES>` is a space separated list of paths of all modified Rust files relative to the root of the repository.
2. **Lint** by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   cargo clippy --all-features <CRATES> -- \
       -D warnings \
       -D clippy::all \
       -D clippy::mem_forget \
       -A clippy::uninlined_format_args
   ```
   where `<CRATES>` is a space separated list of
   `-p <CRATE>` options for all modified crates.
   e.g., `-p ic-crypto -p ic-types` if both were modified.
   Run a single clippy invocation covering all modified crates.

   To determine the crate name, check the `name` field in the nearest
   ancestor `Cargo.toml` relative to the modified file.

   Fix any linting errors.
3. **Build** the directly affected bazel targets by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   TARGETS="$(bazel query 'kind(rule, rdeps(//..., set(<MODIFIED_FILES>), 1))' --keep_going 2>/dev/null)"
   if [ -n "$TARGETS" ]; then
       bazel build $TARGETS
   fi
   ```
   where `<MODIFIED_FILES>` is a space separated list of paths of all modified files relative to the root of the repository.

   Fix all build errors.
4. **Test** the directly affected bazel tests by running the following from the root of the repository:
   ```
   cd "$(git rev-parse --show-toplevel)"
   TESTS="$(bazel query 'kind(".*_test|test_suite", kind(rule, rdeps(//..., set(<MODIFIED_FILES>), 2)))' --keep_going 2>/dev/null)"
   if [ -n "$TESTS" ]; then
       bazel test --test_output=errors $TESTS
   fi
   ```
   (Use a depth of 2 in `rdeps` because tests usually depend on source files indirectly through a `rust_library` for example).

   Fix all test failures.