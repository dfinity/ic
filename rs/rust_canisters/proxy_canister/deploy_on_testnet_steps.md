Step 1: Define a dfx.json file. There is a schema for the `dfx.json` file online.
A sample one if deploying a .wasm file:
```
{
  "canisters": {
    "proxy_canister": {
      "type": "custom",
      "wasm": "proxy_canister.wasm",
      "candid": "proxy_canister.did"
    }
  },
  "defaults": {
    "build": {
      "args": "",
      "packtool": ""
    }
  },
  "output_env_file": ".env",
  "version": 1
}
```

Step 2: Make sure that the Candid file can be generated, as it is required. Assuming a Rust file will be installed on a canister (e.g. `/ic/rs/rust_canisters/proxy_canister/src/main.rs`), then make sure to add at the end of the file `ic_cdk::export_candid!();` along with `use ic_cdk::export_candid;`.

Step 3: Generate .wasm file by running `cargo build --release --target wasm32-unknown-unknown --package proxy_canister`
Take note where the wasm file is being generated as we will be copying it.

Step 4: Generate the candid file by running `candid-extractor proxy_canister.wasm > proxy_canister.did`

Step 5: Setup, build and install the software on the canister
```
# Canister configuration step
dfx canister create --network https://ic0.farm.dfinity.systems --provisional-create-canister-effective-canister-id 5v3p4-iyaaa-aaaaa-qaaaa-ca proxy_canister --no-wallet 

# Canister build step
dfx build --network https://ic0.farm.dfinity.systems

# Install software on canister step
dfx canister install proxy_canister --network https://ic0.farm.dfinity.systems --provisional-create-canister-effective-canister-id 5v3p4-iyaaa-aaaaa-qaaaa-ca proxy_canister
```

Step 6: Make requests to the canister
```
# If in doubt about how the canister method argument should look like, in this case the RemoteHttpRequest record, then just call the method without any argument.
# This will provide a template that you can fill up and then send as an argument.

dfx canister call  --network https://ic0.farm.dfinity.systems  proxy_canister send_request '( record { request = record { url = "https://jsonplaceholder.typicode.com/todos/1"; method = variant { get }; max_response_bytes = null; body = null; transform = null; headers = vec {}; }; cycles = 100 : nat64; })'
```
