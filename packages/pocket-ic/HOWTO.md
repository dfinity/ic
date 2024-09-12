# How to use This Library

You create an empty IC instance by instantiating `PocketIc`: 
```rust 
let pic = PocketIc::new();
```
This constructor will discover an already running instance of the PocketIC Server or launch a fresh one.
It then requests a fresh instance and serves as a unique reference to that instance. When the value is dropped, the instance on the PocketIC Server will be deleted.
To silence the PocketIC server output (in particular, canister and replica logs), you can set the environment variable `POCKET_IC_MUTE_SERVER` (to an arbitrary value).

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

**Attention**: It is strongly discouraged to use the PocketIC library for interacting with a live instance.
Live instances can be made non-live again by disabling auto-progress and disabling the gateway.
This is done by calling `stop_live()` on the instance.
Once this call returns, you can use the PocketIC library for testing again.
The instance will only make progress when you call `tick()` - but the state in which the instance halts is not deterministic.
So be extra careful with tests which are setup with a live phase and which then transition to non-live for the test section. 

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
// stop the HTTP gateway and auto progress
pic.stop_live();
```

## Concurrent update calls

Until version 3.x, submitting ingress messages and executing them was tightly coupled in the method `update_call`.
Since version 4.0.0, the PocketIC server supports concurrent update calls, i.e., first submitting several update calls that are later executed concurrently when awaited.
This is useful for canister testing in the presence of interleaving update calls (e.g., ensuring that locking in critical sections works properly)
and potentially also to speed up tests.

In more detail, calling the method `submit_call` on a PocketIC instance submits an update call for asynchronous execution and returns its message ID, _without making any progress on this message_.
Later, the update call can be awaited by calling the method `await_call` on the PocketIC instance passing the corresponding message ID as an argument. In particular, the method `update_call` corresponds to

```rust
let message_id = pic.submit_call(
    canister_id,
    sender,
    method,
    payload,
)?;
pic.await_call(message_id)
```

and remains available.

Note that all update calls submitted for asynchronous execution are executed concurrently already when any one of them is being awaited using `await_call`.
This means that the update calls need not be awaited concurrently (as is the case for Rust futures that need to be awaited to even start executing).

Here is a sketch on how to submit and await some concurrent update calls:

```rust
let pic = PocketIc::new();
let canister_id = pic.create_canister();
pic.add_cycles(canister_id, INIT_CYCLES);
let wasm = [...];
let arg = encode_one(()).unwrap();
pic.install_canister(canister_id, wasm, arg, None);

let msg_id1 = pic
    .submit_call(
        canister_id,
        Principal::anonymous(),
        "foo",
        encode_one(()).unwrap(),
    )
    .unwrap();
let msg_id2 = pic
    .submit_call(
        canister_id,
        Principal::anonymous(),
        "foo",
        encode_one(()).unwrap(),
    )
    .unwrap();

// trigger concurrent execution of both update calls and block until the first one completes
let res1 = pic.await_call(msg_id1).unwrap();

// resume execution of the second update call if it has not completed yet and block until it completes
let res2 = pic.await_call(msg_id2).unwrap();
```

## Asynchronous PocketIC library

To use the PocketIC library in asynchronous contexts, e.g., within a `tokio::test`,
you can use the `nonblocking` module of the PocketIC library.
Otherwise, the PocketIC library might crash in asynchronous contexts.

Here is a sketch of a `tokio::test`:

```rust
#[tokio::test]
async fn test_counter_canister_async() {
    let pic = pocket_ic::nonblocking::PocketIc::new().await;

    // Create a canister.
    let can_id = pic.create_canister().await;

    [...]

    // Drop the PocketIc instance.
    pic.drop().await;
}
```

Note that the PocketIC instance created using the `nonblocking` module must be dropped manually
as Rust does not yet support asynchronous drop.

## Persisting state of a PocketIC instance

The full state of a PocketIC instance can be persisted and later reused by specifying a state directory
to which the PocketIC server stores the state of the PocketIC instance.
When specified for the very first time, the state directory must be an empty directory
and the content of the state directory should not be modified manually, i.e.,
the content of the state directory should only be modified by the PocketIC server.

Here is a sketch of a test creating and installing a canister and starting with an empty state directory
that contains the full state of the PocketIC instance after the test completes.

```rust
#[test]
fn initialize_state_dir() {
    let state_dir: PathBuf = [...];

    // Create a PocketIC instance with one application subnet,
    // passing an empty state directory.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir)
        .with_application_subnet()
        .build();

    // Create a canister.
    let can_id = pic.create_canister();
    assert_eq!(can_id, Principal::from_text("lxzze-o7777-77777-aaaaa-cai").unwrap());

    pic.add_cycles(can_id, 100_000_000_000_000);
    let can_wasm = [...];
    pic.install_canister(can_id, can_wasm, vec![], None);

    pic.update_call(can_id, Principal::anonymous(), "write", vec![]).unwrap();
}
```

Later a new test can be started resuming from the state of a past PocketIC instance
stored in the state directory.

```rust
#[test]
fn mount_state_dir() {
    let state_dir: PathBuf = [...];

    // Create a PocketIC instance from a state directory,
    // the subnets and their types (application etc.)
    // are loaded from the state directory.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir)
        .build();

    // We can now execute calls on canisters contained in the state directory
    // resuming from their latest state.
    let can_id = Principal::from_text("lxzze-o7777-77777-aaaaa-cai").unwrap();
    pic.query_call(can_id, Principal::anonymous(), "read", vec![]).unwrap();
    pic.update_call(can_id, Principal::anonymous(), "write", vec![]).unwrap();
}
```

## Canister HTTP outcalls

To deterministically test canister HTTP outcalls, you can use a pair of functions provided by the PocketIC library:
- a function `PocketIc::get_canister_http` to retrieve all pending canister HTTP outcalls;
- and a function `PocketIc::mock_canister_http_response` to mock a response for a pending canister HTTP outcall.

Here is a sketch of a test for a canister making canister HTTP outcalls:

```rust
#[test]
fn test_canister_http() {
    let pic = PocketIc::new();

    // Create a canister and charge it with 100T cycles.
    let can_id = pic.create_canister();
    pic.add_cycles(can_id, 100_000_000_000_000);

    // Install the test canister wasm file on the canister.
    let test_wasm = [...];
    pic.install_canister(can_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock a canister http outcall response.
    let arg_bytes = Encode!(&()).unwrap();
    let call_id = pic
        .submit_call(
            can_id,
            Principal::anonymous(),
            "canister_http",
            arg_bytes,
        )
        .unwrap();

    // We need a pair of ticks for the test canister method to make the http outcall
    // and for the management canister to start processing the http outcall.
    pic.tick();
    pic.tick();
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 1);
    let canister_http_request = &canister_http_requests[0];

    let body = b"hello".to_vec();
    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: canister_http_request.subnet_id,
        request_id: canister_http_request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.clone(),
        }),
        additional_responses: vec![],
    };
    pic.mock_canister_http_response(mock_canister_http_response);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    match reply {
        WasmResult::Reply(data) => {
            let http_response: HttpResponse = decode_one(&data).unwrap();
            assert_eq!(http_response.body, body);
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
    };

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);
}
```

Note that the URL of the canister HTTP outcall must either start with `https://` or target `localhost`.

In the live mode (see the section "Live Mode" for more details), the canister HTTP outcalls are processed
by actually making an HTTP request to the URL specified in the canister HTTP outcall.

Here is a sketch of a test for a canister making canister HTTP outcalls in the live mode:

```rust
#[tokio::test]
async fn test_canister_http_live() {
    use candid::{Decode, Encode, Principal};
    use ic_cdk::api::management_canister::http_request::HttpResponse;
    use ic_utils::interfaces::ManagementCanister;

    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let endpoint = pic.make_live(None).await;

    // Retrieve the first canister ID on the application subnet
    // which will be the effective canister ID for canister creation.
    let topology = pic.topology().await;
    let app_subnet = topology.get_app_subnets()[0];
    let effective_canister_id = Principal::from_slice(
        &topology.0.get(&app_subnet).unwrap().canister_ranges[0]
            .start
            .canister_id,
    );

    // Create an agent for the PocketIC instance.
    let agent = ic_agent::Agent::builder()
        .with_url(endpoint)
        .build()
        .unwrap();
    agent.fetch_root_key().await.unwrap();

    // Create a canister and install the test canister wasm.
    let ic00 = ManagementCanister::create(&agent);
    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap();
    let test_wasm = [...];
    ic00.install_code(&canister_id, &test_wasm)
        .call_and_wait()
        .await
        .unwrap();

    // Execute an update call on the test canister making a canister HTTP outcall.
    let arg_bytes = Encode!(&()).unwrap();
    let res = agent
        .update(&canister_id, "canister_http")
        .with_arg(arg_bytes)
        .call_and_wait()
        .await
        .unwrap();
    let http_response = Decode!(&res, HttpResponse).unwrap();
    assert_eq!(http_response.body, b"...");
}
```
