# PocketIC Rust: A Canister Testing Library

PocketIC is a local canister testing solution for the [Internet Computer](https://internetcomputer.org/).  
This testing library works together with the **PocketIC server**, allowing you to interact with your local IC instances and the canisters thereon. 

With PocketIC, testing canisters is as simple as calling rust functions. Here is a minimal example:

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

* Download the latest **PocketIC server** from the [PocketIC repo](https://github.com/dfinity/pocketic).
* Leave the binary in your current working directory, or specify the path to the binary by setting the `POCKET_IC_BIN` environment variable before running your tests.
* Add PocketIC Rust to your project with `cargo add pocket-ic`.
* Import PocketIC with `use pocket_ic::PocketIc`, and create a new PocketIC instance with `let pic = PocketIc::new()` in your Rust code and start testing!

## Examples

For a simple but complete example with the counter canister, [see here](https://github.com/dfinity/ic/blob/master/packages/pocket-ic/tests/tests.rs#L491). 
For an example with cross canister calls on two different subnets with the ledger canister, [see here](https://github.com/dfinity/ic/blob/master/packages/pocket-ic/tests/tests.rs#L19).

For larger test suites with more complex test setups, consider the [OpenChat](https://github.com/open-chat-labs/open-chat/tree/master/backend/integration_tests/src) integration test suite.
Note that instances are shared among testcases there, which is not recommended in general.

## Why PocketIC? 

Canister developers have several options to test their software, but there are tradeoffs: 
- Install and test on the **mainnet**: The 'real' experience, but you pay with real cycles.
- The **replica** provided by DFX: You get the complete stack of a single IC node.
But therefore, you get no cross- or multisubnet functionality, and likely never will.
Replica is quite heavyweight too, because the nonessential components are not abstracted away.
Furthermore, testing with replica is not deterministic. 

Enter **PocketIC**: 
- *Deterministic*: Synchronous control over the IC's execution environment
- *Lightweight*: Mocks the consensus and networking layers
- *Versatile*: Runs as a service on your test system, and accepts HTTP/JSON. This enables:
    - Concurrent and independent IC instances by default - sharing is *possible*
    - Multi-language support: Anyone can write an integration library against the PocketIC REST-API in any language
- Support for multiple subnets and Xnet calls

## How to use this library

You create an empty IC instance by instantiating `PocketIc`: 
```rust 
let pic = PocketIc::new();
```
This constructor will discover an already running instance of the PocketIC Server or launch a fresh one.
It then requests a fresh instance and serves as a unique reference to that instance. When the value is dropped, the instance on the PocketIC Server will be deleted. 

This design promotes *test isolation*, and we recommend to use one `PocketIc` instance per test.
However, it is still possible to share a `PocketIc` instance between tests, but you do so at your own risk concerning 1) determinism and 2) performance (concurrent tests may block each other).

Using a value of the `PocketIc` struct, you interact with the IC itself, e.g. via:
```rust
// IC interface excerpt
fn root_key(&self)  
fn set_time(&self, time: SystemTime) 
fn create_canister(&self) -> CanisterId
fn install_canister(&self, canister_id: CanisterId, wasm_module: Vec<u8>, ...)  
...
```

and you interact with the canisters you have created: 

```rust
// Canister interface excerpt
fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128
fn update_call(&self, canister_id: CanisterId, sender: Principal, method: &str, ...) -> Result<...>
fn upgrade_canister(&self, canister_id: CanisterId, wasm_module: Vec<u8>, ...) -> Result<...>
...
```

You can also use your canister's candid interface like this:
```rust
let MyResult{my_value} = call_candid(&pic, canister_id, "my_candid_method", (arg1, arg2));
```
Note that you have to provide your method arguments `(arg1, arg2)` as a tuple, because it will be encoded to candid automatically. Similarly for the return value, `call_candid` tries to decode the candid-encoded reply from the canister to your rust struct.
For general info on candid, see [here](https://github.com/dfinity/candid/blob/master/spec/Candid.md) and for candid in rust [here](https://github.com/dfinity/cdk-rs). 

See the [examples](#examples) for more. 

## Contributing

Would you like to write canister tests in a different language? Using PocketIC, you can!
The PocketIC server has a JSON/REST interface, against which you may implement any user-facing library in any language.
See for example [PocketIC Python](https://github.com/dfinity/pocketic-py), or [Pic JS](https://www.npmjs.com/package/@hadronous/pic) for JavaScript/TypeScript.

If you decide to contribute, we encourage you to announce it on the [Internet Computer Developer Forum](https://forum.dfinity.org/). 

