# PocketIC Rust: A Canister Testing Library

[PocketIC](https://github.com/dfinity/pocketic) is a local canister testing solution for the [Internet Computer](https://internetcomputer.org/).  
This testing library works together with the **PocketIC server**, allowing you to interact with your local IC instances and the canisters thereon. 

With PocketIC Rust, testing canisters is as simple as calling Rust functions.
Here is a simple example:

```rust
use candid::encode_one;
use pocket_ic::PocketIc;

 #[test]
 fn test_counter_canister() {
    let pic = PocketIc::new();
    // Create an empty canister as the anonymous principal and add cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    
    let wasm_bytes = load_counter_wasm(...);
    pic.install_canister(canister_id, wasm_bytes, vec![], None);
    // 'inc' is a counter canister method.
    call_counter_canister(&pic, canister_id, "inc");
    // Check if it had the desired effect.
    let reply = call_counter_canister(&pic, canister_id, "read");
    assert_eq!(reply, WasmResult::Reply(vec![0, 0, 0, 1]));
 }

fn call_counter_canister(pic: &PocketIc, canister_id: CanisterId, method: &str) -> WasmResult {
    pic.update_call(canister_id, Principal::anonymous(), method, encode_one(()).unwrap())
        .expect("Failed to call counter canister")
}
```

## Getting Started

### Quickstart
* Download the latest **PocketIC server** from the [PocketIC repo](https://github.com/dfinity/pocketic) that is [compatible](https://docs.google.com/document/d/1VYmHUTjrgbzRHtsAyRrI5cj-gWGs7ktTnutPvUMJioU) with the library version you're using.
* Leave the binary in your current working directory, or specify the path to the binary by setting the `POCKET_IC_BIN` environment variable before running your tests.
* Add PocketIC Rust to your project with `cargo add pocket-ic`.
* Import PocketIC with `use pocket_ic::PocketIc`, and create a new PocketIC instance with `let pic = PocketIc::new()` in your Rust code and start testing!

### Examples
For a simple but complete example with the counter canister, see [here](tests/tests.rs#L25).
For an example with cross canister calls on two different subnets with the ledger canister, see [here](tests/tests.rs#L63).

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
