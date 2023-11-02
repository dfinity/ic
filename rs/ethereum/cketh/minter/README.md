# ckETH

This directory contains a proof-of-concept implementation of the chain-key Ethereum system.

## Deploying the Ledger

### Locally

```shell
dfx deploy ledger --argument '(variant { Init = record { minting_account = record { owner = principal "MINTER_CANISTER_ID" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 10_000_000_000; token_symbol = "ckSepoliaETH"; token_name = "Chain key Sepolia Ethereum"; metadata = vec {}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 1_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "USER_PRINCIPAL_ID"; } }})'
```

## Deploying the Minter

### Locally

```shell
dfx deploy minter --argument '(variant {InitArg = record { ethereum_network = variant {Sepolia} ; ecdsa_key_name = "dfx_test_key"; ledger_id = principal "LEDGER_CANISTER_ID" ; next_transaction_nonce = 0 }})'
```

## Converting ETH to ckETH

ckETH deposits require calling a smart contract on the Ethereum chain and passing your principal as a `bytes32` array.
The `principal-to-hex` binary is a utility that lets you convert a principal to the smart contract argument.

```shell
cargo run --bin cketh-principal-to-hex $(dfx identity get-principal)
```

```shell
bazel run //rs/ethereum/cketh/minter:principal_to_hex -- $(dfx identity get-principal)
```

## Converting ckETH to ETH

### Approving the Minter

```shell
dfx canister call ledger icrc2_approve 'record {spender = record { owner = principal "MINTER_CANISTER_ID" }; amount = LARGE_AMOUNT_WEI}'
```

### Withdrawing

The specified amount for the withdrawal must not be greater than the approved amount.

```shell
dfx canister call minter withdraw_eth '(SMALL_AMOUNT_WEI, "YOUR_ETH_ADDRESS")
```
