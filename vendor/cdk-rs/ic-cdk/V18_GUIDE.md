# Version 0.18 Guide

## Introduction

`ic-cdk` v0.18 introduces many new features and changes that improve the developer experience.
This guide covers the major features and changes and provides migration guidance for code written with version 0.17 or earlier.

### How to Upgrade

Update `Cargo.toml`:
```toml
[dependencies]
ic-cdk = "0.18.0"
```

## Features

### New `Call` API

This version introduces a revamped API for inter-canister calls, utilizing a builder pattern for flexible call configuration and execution.

```rust
use ic_cdk::call::Call;
let id : Principal =...;
let method : &str =...;
let res: u32 = Call::bounded_wait(id, method) // Choose the "bounded-wait" constructor
    .with_arg(42)                             // Specify Candid argument
    .with_cycles(1000)                        // Attach cycles
    .await?                                   // Execute the call by awaiting it
    .candid()?;                               // Decode the response bytes as Candid value
```

Please check the [docs](https://docs.rs/ic-cdk/0.18.0/ic_cdk/call/struct.Call.html) for more details.

#### Migration

The functions for inter-canister calls in the `ic_cdk::api::call` module are deprecated in favor of the new `Call` API. These functions were created before the introduction of the [Bounded-Wait Calls](https://internetcomputer.org/docs/references/async-code#ic-call-types) feature. To maintain the same behavior, use the `Call::unbounded_wait()` constructor. You can later evaluate if a specific call should switch to `Call::bounded_wait()`.

| Before                                             | After                                                                                    |
|----------------------------------------------------|------------------------------------------------------------------------------------------|
| `call(id, method, arg)`                            | `Call::unbounded_wait(id, method).with_arg(arg).await?.candid()?`                        |
| `call_raw(id, method, args_raw, payment)`          | `Call::unbounded_wait(id, method).with_raw_args(args_raw).with_cycles(payment).await?`   |
| `call_raw128(id, method, args_raw, payment)`       | `Call::unbounded_wait(id, method).with_raw_args(args_raw).with_cycles(payment).await?`   |
| `call_with_payment(id, method, arg, payment)`      | `Call::unbounded_wait(id, method).with_arg(arg).with_cycles(payment).await?.candid()?`   |
| `call_with_payment128(id, method, arg, payment)`   | `Call::unbounded_wait(id, method).with_arg(arg).with_cycles(payment).await?.candid()?`   |
| `call_with_config(...)`                            | `DecoderConfig` is no longer supported.                                                  |
| `notify(id, method, arg)`                          | `Call::unbounded_wait(id, method).with_arg(arg).oneway()?`                               |
| `notify_raw(id, method, args_raw, payment)`        | `Call::unbounded_wait(id, method).with_raw_args(arg_raw).with_cycles(payment).oneway()?` |
| `notify_with_payment128(id, method, arg, payment)` | `Call::unbounded_wait(id, method).with_arg(arg).with_cycles(payment).oneway()?`          |

> [!NOTE]
> Some deprecated APIs expected a tuple of Candid values as input arguments. Often, there is a single Candid value that needs to be wrapped in parentheses. Therefore, it is recommended to use the `with_arg()` method, which accepts a single `CandidType` value. Use `with_args()` when specifying a Candid tuple.
>
> Similarly, for response decoding, it is recommended to use `candid()`, which decodes to a single `CandidType`. Use `candid_tuple()` when decoding the response as a Candid tuple.

### Futures Ordering Changes

In 0.18, the execution order of `spawn` looks like this:

```rs
runs_first();
spawn(async {
	runs_third().await;
	runs_fourth();
});
runs_second();
```

In contrast, the 0.17 execution order of `spawn` looks like this:

```rs
runs_first();
spawn(async {
	runs_second().await;
	runs_fourth();
});
runs_third();
```

Please check all the places you call `spawn` to ensure that you do not depend on the code in the spawned future running before the code below the `spawn` call. Note that most `spawn` calls are the entire body of timers - if there is no code after `spawn` in the timer, the behavior has not changed.

### Wasm64 Compilation

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

### Custom Decoders/Encoders in Macros

The `update` and `query` macros now support custom argument decoders and return value encoders, while the `init` macro supports custom argument decoders only. This gives full control over how data is serialized and deserialized for canister entry points.

```rust
#[update(decode_with = "decode_args", encode_with = "encode_result")]
fn custom_serialization(a: u32, b: u32) -> (u32, u32) {
    // ...
}

// Custom decoder transforms raw bytes into the function's parameter types
fn decode_args(arg_bytes: Vec<u8>) -> (u32, u32) {
    // Custom deserialization logic here ...
}

// Custom encoder transforms the function's return value into bytes
fn encode_result(result: (u32, u32)) -> Vec<u8> {
    // Custom serialization logic here ...
}
```

It's possible to define generic custom decoders/encoders for use across multiple entry points, enabling alternative serialization formats. The example below demonstrates using Protocol Buffers instead of Candid for wire format:

```rust
use prost::Message;

#[update(decode_with = "from_proto_bytes", encode_with = "to_proto_bytes")]
fn protobuf_onwire1(a: u32) -> u32 {
    a + 42
}

#[update(decode_with = "from_proto_bytes", encode_with = "to_proto_bytes")]
fn protobuf_onwire2(a: String) -> String {
    format!("{} world!", a)
}

// Generic decoder function that works with any Protobuf message
fn from_proto_bytes<T: Message + Default>(bytes: Vec<u8>) -> T {
    T::decode(&bytes[..]).unwrap_or_default()
}

// Generic encoder function that works with any Protobuf message
fn to_proto_bytes<T: Message>(message: T) -> Vec<u8> {
    message.encode_to_vec()
}
```

Please check the [macros end-to-end test](../e2e-tests/src/bin/macros/) for more details.

### Simplified Module Structure

The module hierarchy has been flattened to improve usability and consistency:
- The `api` module provides consistent System API bindings.
- The `management_canister` module facilitates convenient Management Canister calls.
- The `bitcoin_canister` module will soon support direct Bitcoin Canister calls.

#### Migration

Submodules in `api` are now deprecated in favor of root-level modules.
- `api/call` -> `call`
- `api/management_canister` -> `management_canister` & `bitcoin_canister`
- `api/stable` -> `stable`

### Custom Exports (advanced)

For those who exported canister entry points with their own `#[export_name]` calls instead of using the attribute macros, the required boilerplate has changed:

```rs
#[unsafe(export_name = "canister_global_timer")]
pub extern "C" fn canister_global_timer() {
    ic_cdk::futures::in_executor_context(|| {
        /* code goes here */
    });
}
#[unsafe(export_name = "canister_inspect_message")]
pub extern "C" fn canister_inspect_message() {
    ic_cdk::futures::in_query_executor_context(|| {
        /* code goes here */
    })
}
```

Every entry point must encase its code in `in_executor_context` (or for query methods or inspect_message callbacks, `in_query_executor_context`). This sets the panic hook (otherwise every panic message will be `[TRAP] unreachable`) and creates the ability to call `spawn` (which will otherwise panic).

The attribute macros insert this call for you; it is only needed when exporting your own entry points. If you attempt to create a context inside another context it will panic; it is only necessary at the top level.
