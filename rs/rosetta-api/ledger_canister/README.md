# Ledger

This package contains the implementation of ICP ledger canister.

## Deploying locally

Follow the steps below to deploy your own copy of the ledger canister to a local replica.

  1. Build the WebAssembly module of the canister.
     Use can use the following Docker file to build the canister from scratch:
     ```Dockerfile
     FROM rust:1.55.0 as builder

     RUN rustup target add wasm32-unknown-unknown
     RUN apt -yq update && \
         apt -yqq install --no-install-recommends build-essential pkg-config clang cmake && \
         apt autoremove --purge -y && \
         rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

     RUN cargo install --version 0.3.2 ic-cdk-optimizer

     # Hint: set this version to the hash of https://github.com/dfinity/ic commit you want to build.
     ARG IC_VERSION=eba88796cf8dff32f5788c9167cdd8e292b6072a

     RUN git clone https://github.com/dfinity/ic && \
         cd ic && \
         git reset --hard ${IC_VERSION} && \
         rm -rf .git && \
         cd ..

     RUN export CARGO_TARGET_DIR=/ic/rs/target && \
         cd ic/rs/ && \
         cargo build --target wasm32-unknown-unknown --release -p ledger-canister && \
         ic-cdk-optimizer -o $CARGO_TARGET_DIR/ledger-canister.wasm $CARGO_TARGET_DIR/wasm32-unknown-unknown/release/ledger-canister.wasm
     ```

     Copy this dockerfile into `ledger.Dockerfile` and run the following commands to obtain the Wasm module and the interface:
     ```sh
     docker build -m 4g -t ledger-wasm -f ledger.Dockerfile .
     docker run --rm --entrypoint cat ledger-wasm /ic/rs/target/ledger-canister.wasm > ledger.wasm
     docker run --rm --entrypoint cat ledger-wasm /ic/rs/rosetta-api/ledger.did > ledger.private.did
     docker run --rm --entrypoint cat ledger-wasm /ic/rs/rosetta-api/ledger_canister/ledger.did > ledger.public.did
     ```
     Note: the build step might take quite some time depending on your hardware (usually 10–30min).

  1. Make sure you use a fresh version of DFX.
     If you don't have DFX installed, follow instructions on https://smartcontracts.org/ to install it.

  1. If you don't have a DFX the project yet, follow these instructions to create a new dfx project:
     https://smartcontracts.org/docs/developers-guide/cli-reference/dfx-new.html

  1. Copy the file you obtained at the canister build step (`ledger.wasm`, `ledger.private.did`, `ledger.public.did`) into the root of your project.

  1. Add the following canister definition to `dfx.json` file in your project:
     ```json
     {
       "canisters": {
         "ledger": {
           "type": "custom",
           "wasm": "ledger.wasm",
           "candid": "ledger.private.did"
         }
       }
     }
     ```

  1. Start local replica.
     ```sh
     dfx start --background
     ```

  1. Create an new identity that will work as a minting account:
     ```sh
     dfx identity new minter
     dfx identity use minter
     export MINT_ACC=$(dfx ledger account-id)
     ```
     Transfers from the minting account will create `Mint` transactions.
     Transfers to the minting account will create `Burn` transactions.

  1. Switch back to your main identity and record its ledger account identifier.
     ```sh
     dfx identity use default
     export LEDGER_ACC=$(dfx ledger account-id)
     ```

  1. Deploy the ledger canister to your network.
     ```sh
     dfx deploy ledger --argument '(record {minting_account = "'${MINT_ACC}'"; initial_values = vec { record { "'${LEDGER_ACC}'"; record { e8s=100_000_000_000 } }; }; send_whitelist = vec {}})'
     ```

  1. Update the canister definition in `dfx.json` file to use the public candid interface:
     ```json
     {
       "canisters": {
         "ledger": {
           "type": "custom",
           "wasm": "ledger.wasm",
           "candid": "ledger.public.did"
         }
       }
     }
     ```

  1. Check that the canister works:
     ```sh
     $ dfx canister call ledger account_balance '(record { account = '$(python3 -c 'print("vec{" + ";".join([str(b) for b in bytes.fromhex("'$LEDGER_ACC'")]) + "}")')' })'     
     (record { e8s = 100_000_000_000 : nat64 })
     ```

Your local ICP ledger canister is up and running now.
You can now deploy other canisters that need to communicate with the ledger canister.
