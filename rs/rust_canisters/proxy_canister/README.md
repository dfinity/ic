# Proxy Canister
The Proxy Canister is created as a testing canister to verify Canister HTTP call feature behavior.

# Build and install the canister

## Build the canister wasm file
`cd rs/rust_canisters/proxy_canister`
`wasm-pack build --out-dir ./wasm/ --out-name proxy_canister.wasm --release`

## Deploy the canister
`dfx deploy`

# Interface
As the "Canister HTTP Calls" feature currently only supports HTTP "GET" method, only one function is currently 
defined on the Proxy Canister: `fetch_for_me`. This function does nothing but forwards user's HTTP GET request
to targetted remote service from Internet Computer.

For full interface, please check `proxy_canister.did` file.

# Run a test with this canister
This canister is used in 3 system tests: `basic_http.rs`, `timeout_http.rs`, and `node_failure_http.rs`. 

To run a test with this canister, enable `nix-shell` in `ic/rs/` folder, and `cd` into `tests/` folder. Try a command as below to run the `basic_http.rs` test:
```
python3 run-system-tests.py --include-pattern=basic_http --suite=pre_master
```
