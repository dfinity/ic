# ckBTC test clone
The canisters defined in dfx.json and canister_ids.json are used for testing purposes and have the same setup as the ckBTC canisters.
## DO NOT SEND BTC TO ANY ADDRESS THAT COME FROM THOSE CANISTERS


Installing the minter canister:
```
dfx canister --network ic install minter --argument '(variant { Init = record {
    btc_network = variant {Mainnet};
    ledger_id = principal "p3oqo-mqaaa-aaaar-qaaja-cai";
    ecdsa_key_name = "key_1";
    retrieve_btc_min_amount = 10000;
    max_time_in_queue_nanos = 1000000000;
    min_confirmations = opt 2;
    mode = variant { GeneralAvailability };
    kyt_principal = opt principal "p4pw2-biaaa-aaaar-qaajq-cai";
}})'
```

Installing the KYT canister:
```
dfx canister --network ic install kyt --argument '(variant { InitArg = record {
    api_key = "";
    minter_id = principal "psn3s-2yaaa-aaaar-qaaiq-cai";
    maintainers = vec { principal ""};
    mode = variant {Normal};
}})'
```

Installing the Ledger Canister:
```
dfx canister --network ic install ledger --argument '(variant { Init = record{
    token_symbol = "TEX";
    token_name = "Token btc example";
    minting_account = record { owner = principal "psn3s-2yaaa-aaaar-qaaiq-cai"  };
    transfer_fee = 10_000;
    metadata = vec {};
    initial_balances = vec {};
    max_memo_length = opt 80;
    archive_options = record {
        num_blocks_to_archive = 2000;
        trigger_threshold = 1000;
        controller_id = principal "psn3s-2yaaa-aaaar-qaaiq-cai";
    };
}})'
```
