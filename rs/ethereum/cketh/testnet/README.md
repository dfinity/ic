# ckETH

This directory contains the deployed arguments and canister IDs related to ckSepliackSepoliaETH.

## Deploying the Ledger

### Locally

```shell
dfx canister create ledger
dfx deploy ledger --argument '(variant { Init = record { minting_account = record { owner = principal "MINTER_ID" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 10_000_000_000; token_symbol = "ckSepoliaETH"; token_name = "Chain key Sepolia Ethereum"; metadata = vec {}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 1_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "mf7xa-laaaa-aaaar-qaaaa-cai"; } }})'
```

### Mainnet

```
dfx deploy --network ic ledger --argument '(variant { Init = record { minting_account = record { owner = principal "jzenf-aiaaa-aaaar-qaa7q-cai" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 10_000_000_000; token_symbol = "ckSepoliaETH"; token_name = "Chain key Sepolia Ethereum"; metadata = vec {}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 1_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "mf7xa-laaaa-aaaar-qaaaa-cai"; } }})' --mode reinstall --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

## Deploying the Minter

### Locally

```shell
dfx canister create minter
dfx deploy minter --argument '(variant {InitArg = record { ethereum_network = variant {Sepolia} ; ecdsa_key_name = "key_1"; ethereum_contract_address = opt "CONTRACT_ADDRESS" ; ledger_id = principal "'"$(dfx canister id ledger)"'"; ethereum_block_height = variant {Finalized} ; minimum_withdrawal_amount = 10_000_000_000_000_000; next_transaction_nonce = NEXT_NONCE }})'
```

### Mainnet

```
dfx deploy --network ic minter --argument '(variant {InitArg = record { ethereum_network = variant {Sepolia} ; ecdsa_key_name = "key_1"; ethereum_contract_address = opt "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34" ; ledger_id = principal "'"$(dfx canister --network ic id ledger)"'"; ethereum_block_height = variant {Finalized} ; minimum_withdrawal_amount = 10_000_000_000_000_000; next_transaction_nonce = NEXT_NONCE }})' --mode reinstall --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

Note: you can query the next nonce using:

```
curl -X POST 'https://ethereum-sepolia.publicnode.com' \
    --header 'Content-Type: application/json' \
    --data '{
        "jsonrpc":"2.0",
        "method":"eth_getTransactionCount",
        "params":[
            "0x1789F79e95324A47c5Fd6693071188e82E9a3558",
            "latest"
        ],
        "id":1
    }'
```