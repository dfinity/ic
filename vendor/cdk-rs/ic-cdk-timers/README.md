Rust CDK Timers Library
=======================

[![Documentation](https://docs.rs/ic-cdk-timers/badge.svg)](https://docs.rs/ic-cdk-timers/)
[![Crates.io](https://img.shields.io/crates/v/ic-cdk-timers.svg)](https://crates.io/crates/ic-cdk-timers)
[![License](https://img.shields.io/crates/l/ic-cdk-timers.svg)](https://github.com/dfinity/cdk-rs/blob/main/src/ic-cdk-timers/LICENSE)
[![Downloads](https://img.shields.io/crates/d/ic-cdk-timers.svg)](https://crates.io/crates/ic-cdk-timers)
[![CI](https://github.com/dfinity/cdk-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dfinity/cdk-rs/actions/workflows/ci.yml)

This crate provides a library to schedule multiple and periodic tasks on the Internet Computer.

Example
-------

In `Cargo.toml`:

```toml
[dependencies]
ic-cdk-timers = "1.0.0"
```

To schedule a one-shot task to be executed 1s later:

```rust
ic_cdk_timers::set_timer(Duration::from_secs(1), async { ic_cdk::println!("Hello from the future!") });
```

References
----------

1. Internet Computer Developer Guide: [Periodic Tasks and Timers](https://internetcomputer.org/docs/current/developer-docs/backend/periodic-tasks)
2. Example: [Periodic Tasks and Timers](https://github.com/dfinity/examples/tree/master/rust/periodic_tasks) (compares timers and heartbeats).
