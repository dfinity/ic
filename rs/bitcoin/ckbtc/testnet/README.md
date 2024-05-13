# ckTESTBTC deployment

Subnet: `pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`
Wallet: [`mf7xa-laaaa-aaaar-qaaaa-cai`](https://mf7xa-laaaa-aaaar-qaaaa-cai.ic0.app/)

## Build canisters from source

```shell
dfx build --network ic
```

## Installing the minter ([`ml52i-qqaaa-aaaar-qaaba-cai`](https://dashboard.internetcomputer.org/canister/ml52i-qqaaa-aaaar-qaaba-cai))

Notes on init args:

* The ledger id comes from the `canister_ids.json` file.
* Max time in queue is seven minutes, or 420 billion nanoseconds.
* Min retrieve BTC amount is 5K satoshies.
  That's enough to cover the fees for the type of transactions we create.
  Also, it is hard to obtain more than 10K satoshies on the BTC testnet.
* ECDSA key name is "key_1".


```shell
dfx deploy minter --network ic --argument '(record { btc_network = variant { Testnet }; ledger_id = principal "mc6ru-gyaaa-aaaar-qaaaq-cai"; ecdsa_key_name = "key_1"; retrieve_btc_min_amount = 5_000; max_time_in_queue_nanos = 420_000_000_000 })'
```

## Installing the ledger ([`mc6ru-gyaaa-aaaar-qaaaq-cai`](https://dashboard.internetcomputer.org/canister/mc6ru-gyaaa-aaaar-qaaaq-cai))

Notes on init args:

* The minter account is the default account of the ckBTC minter; `ml52i-qqaaa-aaaar-qaaba-cai` comes from the `canister_ids.json` file.
* The transfer fee is 10 ckBTC Satoshis.
* There are no initial balances: the minter is responsible for minting all ckBTC.
* Archive max memory size is 3GiB, or 3221225472 bytes.
  We can afford that much memory because archives store transactions in stable memory.

```shell
dfx deploy ledger --network ic --argument '(record { minting_account = record { owner = principal "ml52i-qqaaa-aaaar-qaaba-cai" }; transfer_fee = 10; token_symbol = "ckTESTBTC"; token_name = "Chain key testnet Bitcoin"; metadata = vec {}; initial_balances = vec {}; max_memo_length = opt 80; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 1_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "mf7xa-laaaa-aaaar-qaaaa-cai" } })'
```

## Installing the index ([`mm444-5iaaa-aaaar-qaabq-cai`](https://dashboard.internetcomputer.org/canister/mm444-5iaaa-aaaar-qaabq-cai))

```shell
dfx deploy index --network ic --argument '(record { ledger_id = principal "mc6ru-gyaaa-aaaar-qaaaq-cai" })'
```

## Upgrading the archive ([`m62lf-ryaaa-aaaar-qaacq-cai`](https://dashboard.internetcomputer.org/canister/m62lf-ryaaa-aaaar-qaacq-cai))

```shell
dfx deploy --network ic archive --argument '(principal "mc6ru-gyaaa-aaaar-qaaaq-cai", 0, opt 3_221_225_472, null)'
```

## KYT ([`pvm5g-xaaaa-aaaar-qaaia-cai`](https://dashboard.internetcomputer.org/canister/pvm5g-xaaaa-aaaar-qaaia-cai))

### Install

```shell
dfx deploy kyt --network ic --argument '(variant { InitArg = record { api_key = ""; maintainers = vec {}; mode = variant { AcceptAll }; minter_id = principal "ml52i-qqaaa-aaaar-qaaba-cai" } })'
```

### Upgrade

```shell
dfx deploy --network ic kyt --argument '(variant { UpgradeArg = record {};})'
```
