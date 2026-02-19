[![Internet Computer portal](https://img.shields.io/badge/InternetComputer-grey?logo=internet%20computer&style=for-the-badge)](https://internetcomputer.org)
[![DFinity Forum](https://img.shields.io/badge/help-post%20on%20forum.dfinity.org-blue?style=for-the-badge)](https://forum.dfinity.org/)
[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?logo=apache&style=for-the-badge)](LICENSE)


# `ic-agent-canister-runtime`

Library that implements the [`ic_canister_runtime`](https://crates.io/crates/ic-canister-runtime) crate's Runtime trait using [`ic-agent`](https://crates.io/crates/ic-agent). 
This can be useful when, e.g., contacting a canister via ingress messages instead of via another canister.

## Usage

Add this to your `Cargo.toml` (see [crates.io](https://crates.io/crates/ic-agent-canister-runtime) for the latest version):

```toml
ic-agent-canister-runtime = "0.1.0"
ic-canister-runtime = "0.1.0"
```

Then, use the library to abstract your code making requests to canisters as follows:
```rust
use ic_agent_canister_runtime::AgentRuntime;
use ic_canister_runtime::Runtime;

let agent = ic_agent::agent::Agent::builder().build().unwrap();
let runtime = AgentRuntime::new(&agent);

// Make a request to the `http_request` example canister's `make_http_post_request` endpoint
// See: https://github.com/dfinity/canhttp/tree/main/examples/http_canister
let http_request_result: String = runtime
    .update_call(canister_id, "make_http_post_request", (), 0)
    .await
    .expect("Call to `http_canister` failed");

assert!(http_request_result.contains("Hello, World!"));
assert!(http_request_result.contains("\"X-Id\": \"42\""));
```

See the [Rust documentation](https://docs.rs/ic-agent-canister-runtime) for more details.

## License

This project is licensed under the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0).