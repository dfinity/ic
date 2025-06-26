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
fn set_time(&self, time: Time)
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

The PocketIC server exposes the ICP's HTTP interface (as defined in the [Interface Specification](https://internetcomputer.org/docs/references/ic-interface-spec#http-interface)) used by the ICP mainnet. This means that PocketIC instances can also be targeted by agent-based tools, e.g., the [Rust](https://crates.io/crates/ic-agent) and [JavaScript](https://www.npmjs.com/package/@dfinity/agent) agents.

Note that PocketIC instances do not "make progress" by default, i.e., they do not execute any messages and time does not advance unless dedicated operations are triggered by separate HTTP requests. The "live" mode enabled by calling the function `PocketIc::make_live()` automates those steps by launching a background thread that

- sets the current time as the PocketIC instance time;
- advances time on the PocketIC instance regularly;
- executes messages on the PocketIC instance;
- executes canister HTTP outcalls of the PocketIC instance.

The function `PocketIc::make_live()` also creates an HTTP gateway serving
  - the ICP's HTTP interface (as defined in the [Interface Specification](https://internetcomputer.org/docs/references/ic-interface-spec#http-interface))
  - and the ICP's HTTP gateway interface (as defined in the [HTTP Gateway Protocol Specification](https://internetcomputer.org/docs/references/http-gateway-protocol-spec))
and returns its URL.

**Attention**: Enabling the "live" mode makes the PocketIC instance non-deterministic! For instance, there is no way to tell in which order messages are going to be executed.
The function `PocketIc::stop_live` can be used to disable the "live" mode: it stops the HTTP gateway and the background thread ensuring progress on the PocketIC instance.
However, the non-deterministic state changes during the "live" mode (e.g., time changes) could affect the PocketIC instance even after disabling the "live" mode.

**Attention**: The "live" mode requires the PocketIC instance to have an NNS subnet.

**Attention**: It is strongly discouraged to override time of a "live" PocketIC instance.

Here is a sketch on how to use the PocketIC library to make an update call in the "live" mode:

```rust
// We create a PocketIC instance with an NNS subnet
// (the "live" mode requires the NNS subnet).
let mut pic = PocketIcBuilder::new()
    .with_nns_subnet()
    .with_application_subnet()
    .build();

// Enable the "live" mode.
let _ = pic.make_live(None);

// Create and install a test canister.
// ...

// Submit an update call to the test canister making a canister http outcall.
let call_id = pic
    .submit_call(
        canister_id,
        Principal::anonymous(),
        "canister_http",
        encode_one(()).unwrap(),
    )
    .unwrap();

// Await the update call without making additional progress (the PocketIC instance
// is already in the "live" mode making progress automatically).
let reply = pic.await_call_no_ticks(call_id).unwrap();

// Process the reply.
// ...
```

Here is a sketch on how to use the IC agent in the "live" mode:

```rust
// We create a PocketIC instance with an NNS subnet
// (the "live" mode requires the NNS subnet).
let mut pic = PocketIcBuilder::new()
    .with_nns_subnet()
    .with_application_subnet()
    .build();

// Enable the "live" mode.
let endpoint = pic.make_live(None);

// We use a tokio runtime to run the asynchronous IC agent.
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
rt.block_on(async {
    // We create an IC agent.
    let agent = ic_agent::Agent::builder()
        .with_url(endpoint)
        .build()
        .unwrap();

    // We fetch the PocketIC (i.e., non-mainnet) root key to successfully verify responses.
    agent.fetch_root_key().await.unwrap();

    // Finally, we use the IC agent in tests.
    // ...
});
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

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);

    // Install the test canister wasm file on the canister.
    let test_wasm = todo!();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall
    // and mock a canister http outcall response.
    let call_id = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "canister_http",
            encode_one(()).unwrap(),
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

    // There should be no more pending canister http outcalls.
    let canister_http_requests = pic.get_canister_http();
    assert_eq!(canister_http_requests.len(), 0);

    // Now the test canister will receive the http outcall response
    // and reply to the ingress message from the test driver.
    let reply = pic.await_call(call_id).unwrap();
    let http_response: Result<HttpRequestResult, (RejectionCode, String)> =
        decode_one(&reply).unwrap();
    assert_eq!(http_response.unwrap().body, body);
}
```

Note that the URL of the canister HTTP outcall must either start with `https://` or target `localhost`.

It is also possible to mock additional (diverging) responses resulting in an error
to test how your canisters handles such an error.
The above example could be updated as follows:

*Warning.* If additional responses are provided, then the total number of responses (one plus the number of additional responses)
must be equal to the size of the subnet on which the canister making the HTTP outcall is deployed,
e.g., 13 for a regular application subnet.

```rust
    let response = |i: u64| {
        CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: format!("hello{}", i / 2).as_bytes().to_vec(),
        })
    };
    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: canister_http_request.subnet_id,
        request_id: canister_http_request.request_id,
        response: response(0),
        additional_responses: (1..13).map(response).collect(),
    };
    pic.mock_canister_http_response(mock_canister_http_response);

    // Now the test canister will receive an error
    // and reply to the ingress message from the test driver
    // relaying the error.
    let reply = pic.await_call(call_id).unwrap();
    let http_response: Result<HttpRequestResult, (RejectionCode, String)> =
        decode_one(&reply).unwrap();
    let (reject_code, err) = http_response.unwrap_err();
    assert!(matches!(reject_code, RejectionCode::SysTransient));
    let expected = "No consensus could be reached. Replicas had different responses. Details: request_id: 0, timeout: 1620328930000000005, hashes: [98387cc077af9cff2ef439132854e91cb074035bb76e2afb266960d8e3beaf11: 2], [6a2fa8e54fb4bbe62cde29f7531223d9fcf52c21c03500c1060a5f893ed32d2e: 2], [3e9ec98abf56ef680bebb14309858ede38f6fde771cd4c04cda8f066dc2810db: 2], [2c14e77f18cd990676ae6ce0d7eb89c0af9e1a66e17294b5f0efa68422bba4cb: 2], [2843e4133f673571ff919808d3ca542cc54aaf288c702944e291f0e4fafffc69: 2], [1c4ad84926c36f1fbc634a0dc0535709706f7c48f0c6ebd814fe514022b90671: 2], [7bf80e2f02011ab0a7836b526546e75203b94e856d767c9df4cb0c19baf34059: 1]";
    assert_eq!(err, expected);
```

In the live mode (see the section "Live Mode" for more details), the canister HTTP outcalls are processed
by actually making an HTTP request to the URL specified in the canister HTTP outcall.

Here is a sketch of a test for a canister making canister HTTP outcalls in the live mode:

```rust
#[tokio::test]
async fn test_canister_http_live() {
    use candid::{Decode, Encode, Principal};
    use pocket_ic::management_canister::HttpRequestResult;
    use ic_utils::interfaces::ManagementCanister;

    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let endpoint = pic.make_live(None).await;

    // Retrieve effective canister id for canister creation.
    let topology = pic.topology();
    let effective_canister_id: Principal = topology.default_effective_canister_id.into();

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

    // Explicitly drop async instance.
    pic.drop().await;
}
```

## Query statistics from the management canister

Similarly to the ICP mainnet, PocketIC collects query call statistics (the number of query calls,
the total amount of instructions executed, and the total request and response payload size)
and makes them available via the `canister_status` endpoint of the management canister.

*Warning.* PocketIC collects query call statistics using the same logic as on the ICP mainnet.
Consequently, please be aware of the following implementation details:
- query calls served from the cache are not accounted for in the statistics (an easy way to bypass
  the cache is to alter the input arguments to your query calls);
- query call statistics are collected as if query calls were evenly (discarding remainders) distributed
  to all nodes of the subnet to which the canister receiving the query calls is deployed
  (e.g., if the number of query calls is less than the number of nodes on the corresponding subnet,
  then the reported number of query calls in the statistics is equal to zero);
- query call statistics are delayed by 2 epochs (one epoch is equal to 60 rounds in PocketIC) and thus
  you need to make sure to execute enough rounds to see query call statistics.

Here is a sketch of a test for collecting query statistics:

```rust
#[test]
fn test_query_stats() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;

    // Create PocketIC instance with a single app subnet.
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // We create a test canister on the app subnet.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let test_wasm = [...];
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // The query stats are still at zero.
    let query_stats = pic.canister_status(canister_id, None).unwrap().query_stats;
    let zero: candid::Nat = 0_u64.into();
    assert_eq!(query_stats.num_calls_total, zero);
    assert_eq!(query_stats.num_instructions_total, zero);
    assert_eq!(query_stats.request_payload_bytes_total, zero);
    assert_eq!(query_stats.response_payload_bytes_total, zero);

    // Execute 13 query calls (one per each app subnet node) on the test canister in each of 4 query stats epochs.
    // Every single query call has different arguments so that query calls are not cached.
    let mut n: u64 = 0;
    for _ in 0..4 {
        for _ in 0..13 {
            pic.query_call(
                canister_id,
                Principal::anonymous(),
                "read",
                n.to_le_bytes().to_vec(),
            )
            .unwrap();
            n += 1;
        }
        // Execute one epoch.
        for _ in 0..60 {
            pic.tick();
        }
    }

    // Now the number of calls should be set to 26 (13 calls per epoch from 2 epochs) due to a delay in query stats aggregation.
    let query_stats = pic.canister_status(canister_id, None).unwrap().query_stats;
    assert_eq!(query_stats.num_calls_total, candid::Nat::from(26_u64));
    assert_ne!(query_stats.num_instructions_total, candid::Nat::from(0_u64));
    assert_eq!(
        query_stats.request_payload_bytes_total,
        candid::Nat::from(208_u64)
    ); // we sent 8 bytes per call
    assert_eq!(
        query_stats.response_payload_bytes_total,
        candid::Nat::from(104_u64)
    ); // the test canister responds with 4 bytes per call
}
```

## IC Bitcoin API via the management canister

In this section, we show how to test your dapp integrating with the [IC Bitcoin API](https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-bitcoin-api)
served by the management canister.

First, we start a `bitcoind` process (the `bitcoind` binary can be downloaded from [here](https://bitcoin.org/en/download)):

```rust
    use tempfile::tempdir;
    // We create a temporary directory to store the `bitcoind` process' configuration and data.
    let tmp_dir = tempdir().unwrap();

    let bitcoind_path = [...];

    let conf_path = tmp_dir.path().join("bitcoin.conf");
    let mut conf = File::create(conf_path.clone()).unwrap();
    conf.write_all(r#"regtest=1
# Dummy credentials for bitcoin RPC.
rpcuser=ic-btc-integration
rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=
rpcauth=ic-btc-integration:cdf2741387f3a12438f69092f0fdad8e$62081498c98bee09a0dce2b30671123fa561932992ce377585e8e08bb0c11dfa"#.as_bytes()).unwrap();
    drop(conf);

    let data_dir_path = tmp_dir.path().join("data");
    create_dir(data_dir_path.clone()).unwrap();

    Command::new(bitcoind_path)
        .arg(format!("-conf={}", conf_path.display()))
        .arg(format!("-datadir={}", data_dir_path.display()))
        .spawn()
        .unwrap();
```

If needed (e.g., for running tests in parallel), you can specify ports to which the `bitcoind` process binds:

```rust
    let port = [...];       // to be used with `PocketIcBuilder::with_bitcoind_addr` (see below for more details)
    let onion_port = [...]; // not needed, but a unique port must be provided
    let rpc_port = [...];   // to be used with `bitcoincore_rpc::Client` (see below for more details)
    Command::new(bitcoind_path)
        .arg(format!("-conf={}", conf_path.display()))
        .arg(format!("-datadir={}", data_dir_path.display()))
        .arg(format!("-bind=0.0.0.0:{}", port))
        .arg(format!("-bind=0.0.0.0:{}=onion", onion_port))
        .arg(format!("-rpcport={}", rpc_port))
        .spawn()
        .unwrap();
```

Now we create a PocketIC instance configured with the Bitcoin subnet and the `bitcoind` process' address and port
(by default, the `bitcoind` process configured with `regtest=1` listens at port 18444):

```rust
    let pic = PocketIcBuilder::new()
        .with_bitcoin_subnet()     // to deploy the bitcoin canister
        .with_ii_subnet()          // to have tECDSA keys available
        .with_application_subnet() // to deploy the test dapp
        .with_bitcoind_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            18444,
        ))
        .build();
```

Because the `bitcoind` process uses the real time, we set the time of the PocketIC instance to be the current time:

```rust
    pic.set_time(SystemTime::now().into());
```

Next we deploy the bitcoin testnet canister (canister ID `g4xu7-jiaaa-aaaan-aaaaq-cai`) on the bitcoin subnet and configure it with `Network::Regtest`
(the bitcoin canister WASM can be downloaded from [here](https://github.com/dfinity/bitcoin-canister/releases/download/release%2F2024-07-28/ic-btc-canister.wasm.gz)):

```rust
    use ic_btc_interface::{Config, Network};
    // The NNS root canister should be the controller of the bitcoin testnet canister.
    let nns_root_canister_id: Principal =
        Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap();
    let btc_canister_id = Principal::from_text("g4xu7-jiaaa-aaaan-aaaaq-cai").unwrap();
    let actual_canister_id = pic
        .create_canister_with_id(Some(nns_root_canister_id), None, btc_canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, btc_canister_id);

    let btc_wasm = [...];
    let args = Config {
        network: Network::Regtest,
        ..Default::default()
    };
    pic.install_canister(
        btc_canister_id,
        btc_wasm,
        Encode!(&args).unwrap(),
        Some(nns_root_canister_id),
    );
```

To mine blocks with rewards credited to a given `bitcoin_address: String`, you can use the JSON-RPC API:

*Notes.*
- By default, the `bitcoind` process configured with `regtest=1` listens at port 18444
  and serves its JSON-RPC API at port 18443.
- We use the dummy authentication specified in the `bitcoind` configuration created above.
- You need to mine at least 100 blocks (Coinbase maturity rule) so that the reward for the first block
  can be transferred to a different address.

```rust
    use bitcoincore_rpc::{bitcoin::Address, Auth, Client, RpcApi};
    let btc_rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass(
            "ic-btc-integration".to_string(),
            "QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=".to_string(),
        ),
    )
    .unwrap();

    let mut n = 101; // must be more than 100 (Coinbase maturity rule)
    // retry generating blocks until the bitcoind is up and running
    let start = std::time::Instant::now();
    loop {
        match btc_rpc.generate_to_address(n, &Address::from_str(&bitcoin_address).unwrap()) {
            Ok(_) => break,
            Err(bitcoincore_rpc::Error::JsonRpc(err)) => {
                if start.elapsed() > std::time::Duration::from_secs(30) {
                    panic!("Timed out when waiting for bitcoind; last error: {}", err);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("Unexpected error when talking to bitcoind: {}", err),
        }
    }
```

For an example of a test canister that can be deployed to an application subnet of the PocketIC instance,
we refer to the basic bitcoin example canister in DFINITY's [examples](https://github.com/dfinity/examples/tree/master/rust/basic_bitcoin).

## VetKd

To test the VetKd feature, you need to create a PocketIC instance with II or fiduciary subnet and enable nonmainnet features:

```rust
    // We create a PocketIC instance consisting of the II and one application subnet.
    let pic = PocketIcBuilder::new()
        .with_ii_subnet()               // this subnet has threshold keys
        .with_application_subnet()      // we deploy the dapp canister here
        .with_nonmainnet_features(true) // the VetKd feature is not available on mainnet yet
        .build();
```

## Running multiple tests from the same state

To speed up running a test suite, it is possible to run multiple tests from the same state
that is only created once at the very beginning and then reused by the individual tests
without interference between the individual tests.
An example of a such setup:

```rust
use std::sync::OnceLock;

const MAINNET_CANISTER_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);

static POCKET_IC_STATE: OnceLock<PocketIcState> = OnceLock::new();

fn init_state() -> &'static PocketIcState {
    POCKET_IC_STATE.get_or_init(|| {
        // create an empty PocketIC state to be set up later
        let state = PocketIcState::new();
        // create a PocketIC instance used to set up the state
        let pic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_state(state)
            .build();

        // set up the state to be used in multiple tests later
        pic.create_canister_with_id(None, None, MAINNET_CANISTER_ID)
            .unwrap();

        // serialize and expose the state
        pic.drop_and_take_state().unwrap()
    })
}

#[test]
fn pocket_ic_init_state_1() {
    // mount the state set up before
    let pic1 = PocketIcBuilder::new()
        .with_read_only_state(init_state())
        .build();

    // assert that the state is properly set up
    assert!(pic1.canister_exists(MAINNET_CANISTER_ID));
}

#[test]
fn pocket_ic_init_state_2() {
    // mount the state set up before
    let pic2 = PocketIcBuilder::new()
        .with_read_only_state(init_state())
        .build();

    // assert that the state is properly set up
    assert!(pic2.canister_exists(MAINNET_CANISTER_ID));
}
```

## Time

The `pocket-ic` crate defines the type `Time` to represent the time of a PocketIC instance
with nanosecond precision on all supported platforms (Windows, MacOS, Linux).
The PocketIC time is used in the functions `PocketIc::get_time`, `PocketIc::set_time`, and `PocketIc::set_certified_time`.

A PocketIC time can be created from a UNIX timestamp in nanoseconds using
the function `Time::from_nanos_since_unix_epoch` and converted back to
a UNIX timestamp in nanoseconds using the function `Time::as_nanos_since_unix_epoch`.

A `system_time: SystemTime` can be converted into `Time` using `system_into.into()`.
A `time: Time` can be converted into `SystemTime` using `time.try_into()`
which fails with an error if the conversion would lead to loss of precision (e.g., on Windows).

Finally, PocketIC times can be compared (for both equality and ordering)
and a `Duration` can be added to a PocketIC time.

## Nonmainnet features

To test a new feature that has not (yet) been rolled out to the ICP mainnet,
the `PocketIcBuilder::with_nonmainnet_features` pattern should be used when creating a new PocketIC instance.

```rust
    // We create a PocketIC instance with features enabled that are not yet available on the ICP mainnet.
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_nonmainnet_features(true)
        .build();
```

To use a new management canister endpoint that is not yet supported by a dedicated (Rust) PocketIC library function,
the generic PocketIC library API, e.g., `PocketIc::update_call_with_effective_principal` should be used:
- the `canister_id` argument should be the management canister principal (`aaaaa-aa`),
- the `effective_principal` argument should be the actual canister or subnet to which the call is targetted
  (e.g., `RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec())` for a `canister_id` of type `Principal`;
  in particular, `RawEffectivePrincipal::None` must not be used),
- and the `payload` argument should be the Candid-encoded binary input to the new management canister endpoint
  (the type of the `payload` argument can either be obtained from a corresponding branch of the public `ic-management-canister-types` crate
  or be defined manually).
