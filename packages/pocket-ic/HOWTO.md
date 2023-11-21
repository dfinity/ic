# How to use This Library

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
fn root_key(&self) -> Option<Vec<u8>>
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

See the [examples](README.md#examples) for more. 
