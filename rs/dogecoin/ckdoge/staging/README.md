# ckDOGE Staging Deployment

* Subnet: `pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`
* minter: [ypu6c-niaaa-aaaar-qbzxa-cai](https://dashboard.internetcomputer.org/canister/ypu6c-niaaa-aaaar-qbzxa-cai)
* ledger: [yivyw-aqaaa-aaaar-qbzxq-cai](https://dashboard.internetcomputer.org/canister/yivyw-aqaaa-aaaar-qbzxq-cai)
* index: [2viw6-tyaaa-aaaar-qbzya-cai](https://dashboard.internetcomputer.org/canister/2viw6-tyaaa-aaaar-qbzya-cai)

## Create canister IDs

### Minter

```bash
dfx canister --ic create minter --subnet pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
```

### Ledger

```bash
dfx canister --ic create ledger --subnet pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
```

### Index

```bash
dfx canister --ic create index --subnet pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
```

## Install canisters

### Minter

About the initialization arguments:

* `get_utxos_cache_expiration_seconds`: cache `get_utxos` results for 60 seconds.
* `retrieve_doge_min_amount`: Mininum retrieve DOGE amount is 50 DOGE or 5B koinus, which is approximatevely $7 (2025.12.18).
* `ecdsa_key_name`: use ECDSA production key named `key_1`.
* `mode`: general availability, anyone can deposit or withdraw.
* `ledger_id`: The ledger id comes from the `canister_ids.json` file, where the ledger is expected to support **u256** balances.
* `max_time_in_queue_nanos`: maximum time a transaction spends in the queue before being sent is ten minutes, or 600 billion nanoseconds.
* `max_num_inputs_in_transaction`: maximum number of inputs UTXOs allowed in a single transaction is 500.
* `utxo_consolidation_threshold`: minimum number of available UTXOs required to trigger consolidation is 10k.
* `doge_network`: Doge network is mainnet.
* `min_confirmations`: minimum number of confirmations on the Doge network required to accept a transaction is 60.


```bash
dfx deploy minter --network ic --argument '
(
  variant {
    Init = record {
      get_utxos_cache_expiration_seconds = opt (60 : nat64);
      retrieve_doge_min_amount = 5_000_000_000 : nat64;
      ecdsa_key_name = "key_1";
      mode = variant { GeneralAvailability };
      ledger_id = principal "yivyw-aqaaa-aaaar-qbzxq-cai";
      max_time_in_queue_nanos = 600_000_000_000 : nat64;
      max_num_inputs_in_transaction = opt (500 : nat64);
      utxo_consolidation_threshold = opt (10_000 : nat64);
      doge_network = variant { Mainnet };
      min_confirmations = opt (60 : nat32);
    }
  }
)
'
```

### Ledger

About the initialization arguments:
* `decimals`: ckDOGE like DOGE uses 8 decimals
* `token_symbol` and `token_name`: is `ckStagingDOGE` since this is a token for test purposes, even if it's deployed on Mainnet and uses Dogecoin mainnet.
* `transfer_fee`: is 1 cent of a DOGE, meaning 1M koinus.
* `minting_account`: is set to the principal of the ckDOGE minter.
* `fee_collector_account`: The fee collector is the `0000000000000000000000000000000000000000000000000000000000000fee` subaccount of the minter canister.
* `max_memo_length`: ckDOGE minter uses memo of length up to 80 bytes.
* `index_principal`: The canister ID comes from the `canister_ids.json` file.
* `feature_flags`: We enable the ICRC-2 support because it's required for the ckDOGE withdrawal flow.


```bash
dfx deploy minter --network ic --argument '
(
  variant {
    Init = record {
      decimals = opt (8 : nat8);
      token_symbol = "ckStagingDOGE";
      transfer_fee = 1_000_000 : nat;
      metadata = vec {
        record {
          "icrc1:logo";
          variant {
            Text = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxnIGNsaXAtcGF0aD0idXJsKCNjbGlwMF85OTdfMzMpIj4KPHBhdGggZD0iTTczIDBDMTEzLjMxMiAwIDE0NiAzMi42ODc4IDE0NiA3M0MxNDYgMTEzLjMxMiAxMTMuMzEyIDE0NiA3MyAxNDZDMzIuNjg3OCAxNDYgMCAxMTMuMzEyIDAgNzNDMCAzMi42ODc4IDMyLjY4NzggMCA3MyAwWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczIDAuNUMxMTMuMDM2IDAuNSAxNDUuNSAzMi45NjM5IDE0NS41IDczQzE0NS41IDExMy4wMzYgMTEzLjAzNiAxNDUuNSA3MyAxNDUuNUMzMi45NjM5IDE0NS41IDAuNSAxMTMuMDM2IDAuNSA3M0MwLjUgMzIuOTYzOSAzMi45NjM5IDAuNSA3MyAwLjVaIiBzdHJva2U9ImJsYWNrIiBzdHJva2Utb3BhY2l0eT0iMC4wNSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE2LjM4NDQgNzcuMjE4OEMxOC40MTIyIDEwNS4yMDIgNDAuNzk4OSAxMjcuNTg5IDY4Ljc4MjIgMTI5LjYxN1YxMzUuOTQzQzM3LjMxMTEgMTMzLjgzNCAxMi4xNjY2IDEwOC42OSAxMC4wNTc3IDc3LjIxODhIMTYuMzg0NFoiIGZpbGw9InVybCgjcGFpbnQwX2xpbmVhcl85OTdfMzMpIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNjguNzgyMiAxNi4zO"
          };
        };
      };
      minting_account = record {
        owner = principal "ypu6c-niaaa-aaaar-qbzxa-cai";
        subaccount = null;
      };
      initial_balances = vec {};
      fee_collector_account = opt record {
        owner = principal "ypu6c-niaaa-aaaar-qbzxa-cai";
        subaccount = opt blob "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0f\ee";
      };
      archive_options = record {
        num_blocks_to_archive = 1_000 : nat64;
        max_transactions_per_response = null;
        trigger_threshold = 2_000 : nat64;
        more_controller_ids = null;
        max_message_size_bytes = null;
        cycles_for_archive_creation = opt (10_000_000_000_000 : nat64);
        node_max_memory_size_bytes = opt (3_221_225_472 : nat64);
        controller_id = principal "mf7xa-laaaa-aaaar-qaaaa-cai";
      };
      max_memo_length = opt (80 : nat16);
      index_principal = opt principal "2viw6-tyaaa-aaaar-qbzya-cai";
      token_name = "ckStagingDOGE";
      feature_flags = opt record { icrc2 = true };
    }
  },
)
'
```

### Index


About the initialization arguments:

* `ledger_id`: The ledger id comes from the `canister_ids.json` file.

```bash
 dfx deploy index --ic --argument '(opt variant { Init = record { ledger_id = principal "yivyw-aqaaa-aaaar-qbzxq-cai" } })'
```
