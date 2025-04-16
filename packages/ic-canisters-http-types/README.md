# ic-canisters-http-types

`ic-canisters-http-types` is a Rust crate that provides types for representing HTTP requests and responses. These types are designed to simplify working with HTTP communication in canister development on the Internet Computer.

## Features

- **`HttpRequest`**: A struct for encapsulating HTTP request details, including method, URL, headers, and body.
- **`HttpResponse`**: A struct for encapsulating HTTP response details, including status code, headers, and body.
- **`HttpResponseBuilder`**: A builder pattern for constructing `HttpResponse` objects.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
ic-canisters-http-types = "0.1.0"
```

#### Example

```rust
use ic_canisters_http_types::{HttpRequest, HttpResponseBuilder};
use serde_bytes::ByteBuf;

fn main() {
    // Create an HTTP request
    let request = HttpRequest {
        method: "GET".to_string(),
        url: "/path/to/resource?query=1".to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: ByteBuf::defaBult(),
    };

    // Extract the path from the request URL
    println!("Path: {}", request.path());

    // Build an HTTP response
    let response = HttpResponseBuilder::ok()
        .header("Content-Type", "application/json")
        .body("{\"message\": \"success\"}")
        .build();

    println!("Response Status: {}", response.status_code);
}
```

## Documentation
For detailed documentation, visit the [Rust Docs](https://docs.rs/ic-canisters-http-types).

## License
This project is licensed under the [Apache License 2.0](LICENSE).

## Contributing
Contributions are welcome! Please open an issue or submit a pull request if you have suggestions or improvements.