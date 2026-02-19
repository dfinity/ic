[![Internet Computer portal](https://img.shields.io/badge/InternetComputer-grey?logo=internet%20computer&style=for-the-badge)](https://internetcomputer.org)
[![DFinity Forum](https://img.shields.io/badge/help-post%20on%20forum.dfinity.org-blue?style=for-the-badge)](https://forum.dfinity.org/)
[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?logo=apache&style=for-the-badge)](LICENSE)


# canhttp

Library to make [HTTPs outcalls](https://internetcomputer.org/https-outcalls) from a canister on the Internet Computer, leveraging the modularity of the [tower framework](https://rust-lang.guide/guide/learn-async-rust/tower.html).

## Usage

Add this to your `Cargo.toml` (see [crates.io](https://crates.io/crates/canhttp) for the latest version):

```toml
canhttp = "0.2.1"
```

Then, use the library to create an HTTP POST request, as follows:
```rust
let request = http::Request::post("https://httpbin.org/anything")
    .max_response_bytes(1_000)
    .header("X-Id", "42")
    .body("Hello, World!".as_bytes().to_vec())
    .unwrap();

let response = http_client()
    .ready()
    .await
    .expect("Client should be ready")
    .call(request)
    .await
    .expect("Request should succeed");
```

Complete examples are available [here](examples) and see also the [Rust documentation](https://docs.rs/canhttp) for more details.

## Cargo Features

### Feature `http`

Offers middleware that transforms a low-level service that uses Candid types into one that uses types from the [http](https://crates.io/crates/http) crate. See the [`http_canister`](examples/http_canister) for a complete example.

### Feature `json`

Offers middleware that transforms a low-level service that transmits bytes into one that transmits JSON payloads. See the [`json_rpc_canister`](examples/json_rpc_canister) for a complete example.

### Feature `multi`

Make multiple calls in parallel and handle their multiple results. See the [`multi_canister`](examples/multi_canister) for a complete example.

## License

This project is licensed under the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0).