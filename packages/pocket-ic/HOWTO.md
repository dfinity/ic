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

## Live Mode

Since version 4.0.0, the PocketIC server also exposes the IC's HTTP interface, just like the IC mainnet and the replica launched by dfx. This means that PocketIC instances can now be targeted by agent-based tools (agent.rs, agent.js, IC-Repl, etc). Note that PocketIC instances, if launched in the regular way, do not "make progress" by themselves, i.e., the state machines that represent the IC do not execute any messages without a call to `tick()` and their timestamps do not advance without a call to `advance_time(...)`. But the agent-based tools expect their target to make progress automatically (as the IC mainnet and the replica launched by dfx do) and use the current time as the IC time, since they dispatch asynchronous requests and poll for the result, checking for its freshness with respect to the current time.

For that reason, you need to explicitly make an instance "live" by calling `make_live()` on it. This will do three things: 

- It launches a thread that calls `tick()` and `advance_time(...)` on the instance regularly - several times per second. 
- It creates a gateway (like icx-proxy for the replica via dfx) which points to this live instance.
- It returns a gateway URL which can then be passed to agent-like tools.

Of course, other instances on the same PocketIC server remain unchanged - neither do they receive `tick`s nor can the gateway route requests to them. 

**Attention**: Enabling auto-progress makes instances non-deterministic! There is no way to guarantee message order when agents dispatch async requests, which may interleave with each other and with the `tick`s from the auto-progress thread. If you need determinism, use the old, manually-`tick`ed API. 

Live instances can be made deterministic again by disabling auto-progress and disabling the gateway. This is done by calling `make_deterministic` on the instance. Once this call returns, the instance will only continue to make progress when you call `tick` - but the state in which the instance halts is not deterministic. So be extra careful with tests which are setup with a live phase and which then transition to non-live for the test section. 

Here is a sketch on how to use the live mode: 

```rust
let mut pic = PocketIcBuilder::new()
    .with_nns_subnet()
    .with_application_subnet()
    .build();
let endpoint = pic.make_live(None);
// the local agent needs a runtime
let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
let res = rt.block_on(async {
    let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
    // proof that the agent can communicate with the instance
    agent.fetch_root_key().await.unwrap();
    // do something useful with the agent
    let res = agent.[...]
    res
});
// stop the HTTP gateway and make instance deterministic
pic.make_deterministic();
```

