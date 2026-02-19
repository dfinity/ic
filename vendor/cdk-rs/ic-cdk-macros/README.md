[![Documentation](https://docs.rs/ic-cdk-macros/badge.svg)](https://docs.rs/ic-cdk-macros/)
[![Crates.io](https://img.shields.io/crates/v/ic-cdk-macros.svg)](https://crates.io/crates/ic-cdk-macros)
[![License](https://img.shields.io/crates/l/ic-cdk-macros.svg)](https://github.com/dfinity/cdk-rs/blob/main/LICENSE)
[![Downloads](https://img.shields.io/crates/d/ic-cdk-macros.svg)](https://crates.io/crates/ic-cdk-macros)
[![CI](https://github.com/dfinity/cdk-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dfinity/cdk-rs/actions/workflows/ci.yml)

# ic-cdk-macros

This crate contains a collection of procedural macros that are utilized within the `ic-cdk` crate.

The macros are re-exported in `ic-cdk`, and you can find their documentation [there](https://docs.rs/ic-cdk/latest/ic_cdk).

---

The macros fall into two categories:

* To register functions as canister entry points
* To export Candid definitions

## Register functions as canister entry points

These macros are directly related to the [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#entry-points).

* [`init`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.init.html)
* [`pre_upgrade`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.pre_upgrade.html)
* [`post_upgrade`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.post_upgrade.html)
* [`inspect_message`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.inspect_message.html)
* [`heartbeat`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.heartbeat.html)
* [`on_low_wasm_memory`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.on_low_wasm_memory.html)
* [`update`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.update.html)
* [`query`](https://docs.rs/ic-cdk/latest/ic_cdk/attr.query.html)

## Export Candid definitions

* [`export_candid`](https://docs.rs/ic-cdk/latest/ic_cdk/macro.export_candid.html)

Check [Generating Candid files for Rust canisters](https://internetcomputer.org/docs/current/developer-docs/backend/candid/generating-candid/) for more details.
