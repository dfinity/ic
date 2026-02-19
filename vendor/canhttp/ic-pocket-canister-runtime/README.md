[![Internet Computer portal](https://img.shields.io/badge/InternetComputer-grey?logo=internet%20computer&style=for-the-badge)](https://internetcomputer.org)
[![DFinity Forum](https://img.shields.io/badge/help-post%20on%20forum.dfinity.org-blue?style=for-the-badge)](https://forum.dfinity.org/)
[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?logo=apache&style=for-the-badge)](LICENSE)

# `ic-pocket-canister-runtime`

Implementation of the [`ic_canister_runtime`](https://crates.io/crates/ic-canister-runtime) crate's `Runtime` trait for [PocketIC](https://internetcomputer.org/docs/building-apps/test/pocket-ic) allowing to mock
[HTTPs outcalls](https://internetcomputer.org/https-outcalls).

## Usage

Add this to your `Cargo.toml` (see [crates.io](https://crates.io/crates/ic-pocket-canister-runtime) for the latest version):

```toml
ic-canister-runtime = "0.1.0"
ic-pocket-canister-runtime = "0.1.0"
```

Then, use the library to mock HTTP outcalls for canister deployed with PocketIC, as follows:
```rust
use ic_canister_runtime::Runtime;
use ic_pocket_canister_runtime::{
    AnyCanisterHttpRequestMatcher, CanisterHttpReply, MockHttpOutcallsBuilder,
    MockHttpRuntime
};
use pocket_ic::nonblocking::PocketIc;

let mocks = MockHttpOutcallsBuilder::new()
    .given(AnyCanisterHttpRequestMatcher)
    .respond_with(
        CanisterHttpReply::with_status(200)
            .with_body(r#"{"data": "Hello, World!", "headers": {"X-Id": "42"}}"#)
    );

let pocket_ic = PocketIc::new().await;
let runtime = MockHttpRuntime::new(&pocket_ic, Principal::anonymous())
    .with_http_mocks(mocks.build());

let http_request_result: String = runtime
    .update_call(canister_id, "make_http_post_request", (), 0)
    .await
    .expect("Call to `http_canister` failed");

assert!(http_request_result.contains("Hello, World!"));
assert!(http_request_result.contains("\"X-Id\": \"42\""));
```

See the [Rust documentation](https://docs.rs/ic-pocket-canister-runtime) for more details.

## License

This project is licensed under the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0).