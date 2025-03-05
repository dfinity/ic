# PocketIC Rust: A Canister Testing Library

[PocketIC](https://github.com/dfinity/pocketic) is a local canister testing solution for the [Internet Computer](https://internetcomputer.org/).  
This testing library works together with the **PocketIC server**, allowing you to interact with your local IC instances and the canisters thereon. 

With PocketIC Rust, testing canisters is as simple as calling Rust functions.
Here is a simple example:

```rust
use candid::{Principal, encode_one};
use pocket_ic::PocketIc;

// 2T cycles
const INIT_CYCLES: u128 = 2_000_000_000_000;

#[test]
fn test_counter_canister() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the counter canister wasm file on the canister.
    let counter_wasm = todo!();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    // Make some calls to the canister.
    let reply = call_counter_can(&pic, canister_id, "read");
    assert_eq!(reply, vec![0, 0, 0, 0]);
    let reply = call_counter_can(&pic, canister_id, "write");
    assert_eq!(reply, vec![1, 0, 0, 0]);
    let reply = call_counter_can(&pic, canister_id, "write");
    assert_eq!(reply, vec![2, 0, 0, 0]);
    let reply = call_counter_can(&pic, canister_id, "read");
    assert_eq!(reply, vec![2, 0, 0, 0]);
}

fn call_counter_can(pic: &PocketIc, canister_id: Principal, method: &str) -> Vec<u8> {
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        method,
        encode_one(()).unwrap(),
    )
    .expect("Failed to call counter canister")
}
```

## Getting Started

### Quickstart
* Download the latest **PocketIC server** from the [PocketIC repo](https://github.com/dfinity/pocketic) that is [compatible](https://docs.google.com/document/d/1VYmHUTjrgbzRHtsAyRrI5cj-gWGs7ktTnutPvUMJioU) with the library version you're using.
* Ungzip the downloaded file.
* On UNIX: make the downloaded file executable.
* Specify the path to the binary by using the function `PocketIcBuilder::with_server_binary` or the environment variable `POCKET_IC_BIN`.
* Add PocketIC Rust to your project with `cargo add pocket-ic`.
* Import PocketIC with `use pocket_ic::PocketIc`, and create a new PocketIC instance with `let pic = PocketIc::new()` in your Rust code and start testing!

### Examples
For simple but complete examples, see [integration tests](tests/tests.rs).

To see a minimalistic setup of PocketIC in a Rust project, check out the [ICP Hello World Rust](https://github.com/dfinity/icp-hello-world-rust/blob/main/README.md#testing-your-project) repository.

For larger test suites with more complex test setups, consider the [OpenChat](https://github.com/open-chat-labs/open-chat/tree/master/backend/integration_tests/src) integration test suite.
Note that instances are shared among test cases there, which is not recommended in general.

## Documentation
* [How to use this library](HOWTO.md)
* [API documentation](https://docs.rs/pocket-ic/)
* [PocketIC repo](https://github.com/dfinity/pocketic)
* [PocketIC server compatibility](https://docs.google.com/document/d/1VYmHUTjrgbzRHtsAyRrI5cj-gWGs7ktTnutPvUMJioU)
* [Why PocketIC](https://github.com/dfinity/pocketic#why-pocketic)
* [Changelog](CHANGELOG.md)
* [Source code](.)

## Contributing
If you decide to contribute, we encourage you to announce it on the [Forum](https://forum.dfinity.org/)!
