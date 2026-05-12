# Proposal to install the ckDOGE minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `990e96bf57d4abacddab0b34f0a0ec9e8c31ee0f`

New compressed Wasm hash: `21ae3a035da7ff8154d201f0a49ae53b95a1d5de361b4f14c91be852a722d533`

Install args hash: `f13104e17e9fdfb2b2bc32d9ab5ef76e8f9af54c2e5abcc4d0d1f47c289a0904`

Target canister: `eqltq-xqaaa-aaaar-qb3vq-cai`

---

## Motivation

This proposal installs the mainnet ckDOGE minter to the governance-controlled canister ID [`eqltq-xqaaa-aaaar-qb3vq-cai`](https://dashboard.internetcomputer.org/canister/eqltq-xqaaa-aaaar-qb3vq-cai) on subnet [`pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`](https://dashboard.internetcomputer.org/subnet/pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae).


## Install args

```bash
git fetch
git checkout 990e96bf57d4abacddab0b34f0a0ec9e8c31ee0f
didc encode -d rs/dogecoin/ckdoge/minter/ckdoge_minter.did -t '(MinterArg)' '
(
  variant {
    Init = record {
      doge_network = variant { Mainnet };
      ledger_id = principal "efmc5-wyaaa-aaaar-qb3wa-cai";
      ecdsa_key_name = "key_1";
      deposit_doge_min_amount = opt (100_000_000 : nat64);
      retrieve_doge_min_amount = 5_000_000_000 : nat64;
      max_time_in_queue_nanos = 600_000_000_000 : nat64;
      min_confirmations = opt (60 : nat32);
      mode = variant { GeneralAvailability };
      get_utxos_cache_expiration_seconds = opt (60 : nat64);
      utxo_consolidation_threshold = opt (10_000 : nat64);
      max_num_inputs_in_transaction = opt (500 : nat64);
    }
  }
)
' | xxd -r -p | sha256sum
```

About the initialization arguments:

* `doge_network`: Doge network is mainnet.
* `ledger_id`: The governance-controlled ckDOGE ledger is [`efmc5-wyaaa-aaaar-qb3wa-cai`](https://dashboard.internetcomputer.org/canister/efmc5-wyaaa-aaaar-qb3wa-cai).
* `ecdsa_key_name`: Use the ECDSA production key named `key_1`.
* `deposit_doge_min_amount`: The minimum deposit DOGE amount is 1 DOGE or 100_000_000 koinus, which is approximately $0.1 (2026.01.30).
* `retrieve_doge_min_amount`: The minimum retrieve DOGE amount is 50 DOGE or 5B koinus, which is approximately $5.7 (2026.01.30).
* `max_time_in_queue_nanos`: The maximum time a transaction spends in the queue before being sent is ten minutes, or 600 billion nanoseconds.
* `min_confirmations`: The minimum number of confirmations on the Doge network required to accept a transaction is 60.
* `mode`: General availability, anyone can deposit or withdraw.
* `get_utxos_cache_expiration_seconds`: Cache `get_utxos` results for 60 seconds.
* `utxo_consolidation_threshold`: The minimum number of available UTXOs required to trigger consolidation is 10k.
* `max_num_inputs_in_transaction`: The maximum number of inputs UTXOs allowed in a single transaction is 500.

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 990e96bf57d4abacddab0b34f0a0ec9e8c31ee0f
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckdoge-minter.wasm.gz
```
