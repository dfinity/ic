# ckBTC mainnet deployment

Root canister id: `r7inp-6aaaa-aaaaa-aaabq-cai`.
Subnet: `pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`


## Installing the minter ([`mqygn-kiaaa-aaaar-qaadq-cai`](https://dashboard.internetcomputer.org/canister/mqygn-kiaaa-aaaar-qaadq-cai))

Notes on init args:

* The ledger id comes from the `canister_ids.json` file.
* Max time in queue is ten minutes, or 600 billion nanoseconds.
* We set a very conservative requirement of at least 72 transaction confirmations.
* Min retrieve BTC amount is 10K satoshi.
  That's enough to cover the fees for the type of transactions we create.
* ECDSA key name is "key_1".

Encoding the init args:

```shell
didc encode -d ../minter/ckbtc_minter.did -t '(InitArgs)' '(record { mode = variant { ReadOnly }; btc_network = variant { Mainnet }; ledger_id = principal "mxzaz-hqaaa-aaaar-qaada-cai"; ecdsa_key_name = "key_1"; min_confirmations = opt 72; retrieve_btc_min_amount = 10_000; max_time_in_queue_nanos = 600_000_000_000 })' | xxd -r -p > minter_arg.bin
```

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id mqygn-kiaaa-aaaar-qaadq-cai \
    --mode install \
    --wasm-module-path ./ic-ckbtc-minter.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg minter_arg.bin \
    --summary-file ./minter_proposal.md
```

## Installing the ledger ([`mxzaz-hqaaa-aaaar-qaada-cai`](https://dashboard.internetcomputer.org/canister/mxzaz-hqaaa-aaaar-qaada-cai))

Notes on init args:

* The minter account is the default account of the ckBTC minter; `mqygn-kiaaa-aaaar-qaadq-cai` comes from the `canister_ids.json` file.
* The transfer fee is 10 ckBTC Satoshis.
* There are no initial balances: the minter is responsible for minting all ckBTC.
* Archive max memory size is 20GiB, or 21_474_836_480 bytes.
  We can afford that much memory because archives store transactions in stable memory.

Encoding the init args:

```shell
didc encode -d ../../../rosetta-api/icrc1/ledger/icrc1.did -t '(InitArgs)' '(record { minting_account = record { owner = principal "mqygn-kiaaa-aaaar-qaadq-cai" }; transfer_fee = 10; token_symbol = "ckBTC"; token_name = "Chain Key Bitcoin"; metadata = vec {}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 100_000_000_000_000; node_max_memory_size_bytes = opt 21_474_836_480; controller_id = principal "r7inp-6aaaa-aaaaa-aaabq-cai" } })' | xxd -r -p > ledger_arg.bin
```

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
    --mode install \
    --wasm-module-path ./ic-icrc1-ledger.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg ledger_arg.bin \
    --summary-file ./ledger_proposal.md
```

## Installing the index ([`n5wcd-faaaa-aaaar-qaaea-cai`](https://dashboard.internetcomputer.org/canister/n5wcd-faaaa-aaaar-qaaea-cai))

Encoding the init args:

```shell
didc encode -d ../../../rosetta-api/icrc1/index/index.did -t '(InitArgs)' '(record { ledger_id = principal "mxzaz-hqaaa-aaaar-qaada-cai" })' | xxd -r -p > index_arg.bin
```

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id n5wcd-faaaa-aaaar-qaaea-cai \
    --mode install \
    --wasm-module-path ./ic-icrc1-index.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg index_arg.bin \
    --summary-file ./index_proposal.md
```

