[![Documentation](https://docs.rs/ic-cdk/badge.svg)](https://docs.rs/ic-cdk/)
[![Crates.io](https://img.shields.io/crates/v/ic-cdk.svg)](https://crates.io/crates/ic-cdk)
[![License](https://img.shields.io/crates/l/ic-cdk.svg)](https://github.com/dfinity/cdk-rs/blob/main/LICENSE)
[![Downloads](https://img.shields.io/crates/d/ic-cdk.svg)](https://crates.io/crates/ic-cdk)
[![CI](https://github.com/dfinity/cdk-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dfinity/cdk-rs/actions/workflows/ci.yml)

# ic-cdk

Canister Developer Kit for the Internet Computer.

## Background

On the Internet Computer, smart contracts come in the form of canisters which are WebAssembly modules.

Canisters expose entry points which can be called both by other canisters and by parties external to the IC.

This library aims to provide a Rust-ergonomic abstraction to implement Canister entry points.

## Getting Started

In Cargo.toml:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
ic-cdk = "0.19"
candid = "0.10" # required if you want to define Candid data types
```

Then in Rust source code:

```rust
#[ic_cdk::query]
fn hello() -> String {
    "world".to_string()
}
```

This will register a **query** entry point named `hello`.

## Compilation

### Stable Target: `wasm32-unknown-unknown`

```sh
cargo build --target wasm32-unknown-unknown
```

### Experimental Target: `wasm64-unknown-unknown`

No changes to the source code are required. However, setting up the Rust toolchain for Wasm64 support requires some additional steps.

1. Install nightly toolchain: 
```bash
rustup toolchain install nightly
```
2. Add rust-src component:
```bash
rustup component add rust-src --toolchain nightly
```
3. Build with necessary flags:
```bash
cargo +nightly build -Z build-std=std,panic_abort --target wasm64-unknown-unknown
```

## Macros

This library re-exports macros defined in `ic-cdk-macros` crate.

The macros fall into two categories:

* To register functions as canister entry points
* To export Candid definitions

### Register functions as canister entry points

These macros are directly related to the [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#entry-points).

* [`init`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.init.html)
* [`pre_upgrade`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.pre_upgrade.html)
* [`post_upgrade`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.post_upgrade.html)
* [`inspect_message`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.inspect_message.html)
* [`heartbeat`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.heartbeat.html)
* [`on_low_wasm_memory`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.on_low_wasm_memory.html)
* [`update`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.update.html)
* [`query`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.query.html)

Canister entry points can be `async`. The CDK embeds an asynchronous executor. Unfortunately anything `tokio`-specific cannot be used.
Use the [`spawn`](https://docs.rs/ic-cdk/latest/ic_cdk/futures/fn.spawn.html) function to run more asynchronous functions in
the background. Panics can cause async tasks to cancel partway through; read the documentation for the 
[`futures`](https://docs.rs/ic-cdk/latest/ic_cdk/futures/index.html) module for more information.

### Export Candid definitions

* [`export_candid`](https://docs.rs/ic-cdk/latest/ic_cdk/macro.export_candid.html)

Check [Generating Candid files for Rust canisters](https://internetcomputer.org/docs/current/developer-docs/backend/candid/generating-candid/) for more details.

## More examples

The [examples repository](https://github.com/dfinity/examples/tree/master/rust) offers numerous Rust examples demonstrating how to build functional Rust canisters.

## Manage Data Structures in Stable Memory

For managing larger datasets and multiple data structures in stable memory, consider using the [`ic-stable-structures`](https://crates.io/crates/ic-stable-structures) crate. While the `ic_cdk::storage::{stable_save, stable_restore}` API is straightforward, it may not be efficient for larger datasets. The `ic-stable-structures` crate provides more scalable solutions for such scenarios.
