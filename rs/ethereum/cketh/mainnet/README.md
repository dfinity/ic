This directory contains the deployed arguments and canister IDs related to ckETH.

The canisters have been create on pzp6e, the fiduciary subnet.

The minter's Ethereum address is: 0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80.

The Helper Contract address is: [0x7574eB42cA208A4f6960ECCAfDF186D627dCC175](https://etherscan.io/address/0x7574eB42cA208A4f6960ECCAfDF186D627dCC175)

## Prerequisites

1. Build the `ic-admin` command.
```shell
bazel build //rs/registry/admin:ic-admin
```

2. Install the [`didc`](https://github.com/dfinity/candid/releases/latest) tool.

## Installing the [ledger](https://dashboard.internetcomputer.org/canister/ss2fx-dyaaa-aaaar-qacoq-cai)

Encoding the init args:

```shell
didc encode -d ../../../rosetta-api/icrc1/ledger/ledger.did -t '(LedgerArg)' '(variant { Init = record { minting_account = record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai" }; fee_collector_account = opt record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai"; subaccount = opt blob "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0f\ee"; }; transfer_fee = 2_000_000_000_000; token_symbol = "ckETH"; token_name = "ckETH"; feature_flags = opt record { icrc2 = true }; metadata = vec { record { "icrc1:logo"; variant { Text = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45NEMzNy4zMDg3IDEzMy44NjcgMTIuMTMzIDEwOC42OTEgMTAuMDYwNSA3Ny4yMDUySDE2LjM4MzdaIiBmaWxsPSJ1cmwoI3BhaW50MF9saW5lYXJfMTEwXzU4NikiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02OC43NjQ2IDE2LjM1MzRDNDAuNzYzOCAxOC40MDM2IDE4LjQwMzcgNDAuNzYzNyAxNi4zNTM1IDY4Ljc2NDZMMTAuMDMwMyA2OC43NjQ2QzEyLjEwMjcgMzcuMjc4NCAzNy4yNzg1IDEyLjEwMjYgNjguNzY0NiAxMC4wMzAyTDY4Ljc2NDYgMTYuMzUzNFoiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMjkuNjE2IDY4LjczNDNDMTI3LjU2NiA0MC43MzM0IDEwNS4yMDYgMTguMzczMyA3Ny4yMDUxIDE2LjMyMzFMNzcuMjA1MSA5Ljk5OTk4QzEwOC42OTEgMTIuMDcyNCAxMzMuODY3IDM3LjI0ODEgMTM1LjkzOSA2OC43MzQzTDEyOS42MTYgNjguNzM0M1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl8xMTBfNTg2KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03My4xOTA0IDMxVjYxLjY4MThMOTkuMTIzIDczLjI2OTZMNzMuMTkwNCAzMVoiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAzMUw0Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA2MS42ODE4VjMxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczLjE5MDQgOTMuMTUyM1YxMTRMOTkuMTQwMyA3OC4wOTg0TDczLjE5MDQgOTMuMTUyM1oiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAxMTRWOTMuMTQ4OEw0Ny4yNTQ0IDc4LjA5ODRMNzMuMTkwNCAxMTRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNNzMuMTkwNCA4OC4zMjY5TDk5LjEyMyA3My4yNjk2TDczLjE5MDQgNjEuNjg4N1Y4OC4zMjY5WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC4yIi8+CjxwYXRoIGQ9Ik00Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA4OC4zMjY5VjYxLjY4ODdMNDcuMjU0NCA3My4yNjk2WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC42Ii8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU4NiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTg2IiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==" }}}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 100_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "r7inp-6aaaa-aaaaa-aaabq-cai" } } })' | xxd -r -p > ledger_arg.bin
```

Notes on init args:

1. sv3dd-oaaaa-aaaar-qacoa-cai is the minter canister (see below).
2. The fee collector is the 0000000000000000000000000000000000000000000000000000000000000fee subaccount of the minter canister.
3. The transfer fee is 2_000_000_000_000, which is around 0.004 USD, roughly in the same bullpark as ckBTC transfer fees of 10 satoshi.
4. We enable the ICRC-2 support because it's required for the ETH withdrawal flow.

Installing the canister:

```shell
../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id ss2fx-dyaaa-aaaar-qacoq-cai \
    --mode install \
    --wasm-module-path ./ic-icrc1-ledger-u256.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg ledger_arg.bin \
    --summary-file ./ledger_proposal.md
```

## Installing the [minter](https://dashboard.internetcomputer.org/canister/sv3dd-oaaaa-aaaar-qacoa-cai)

Encoding the init args:

```shell
didc encode -d ../minter/cketh_minter.did -t '(MinterArg)' '(variant { InitArg = record { ethereum_network = variant { Mainnet }; ecdsa_key_name = "key_1"; ethereum_contract_address = opt "0x7574eB42cA208A4f6960ECCAfDF186D627dCC175"; ledger_id = principal "ss2fx-dyaaa-aaaar-qacoq-cai"; ethereum_block_height = variant { Finalized }; minimum_withdrawal_amount = 30_000_000_000_000_000; next_transaction_nonce = 0; last_scraped_block_number = 18676637 } })' | xxd -r -p > minter_arg.bin
```

Notes on the init args:

1. The minimum withdrawal amount of 0.03 ETH (30_000_000_000_000_000 wei) is a rough equivalent of 60 USD as of November 30, 2023.
2. 18676637 is the Ethereum block in which the helper contract was installed.

Installing the canister:

```shell
../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id sv3dd-oaaaa-aaaar-qacoa-cai \
    --mode install \
    --wasm-module-path ./ic-cketh-minter.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg minter_arg.bin \
    --summary-file ./minter_proposal.md
```

## Installing the [index](https://dashboard.internetcomputer.org/canister/s3zol-vqaaa-aaaar-qacpa-cai)


Encoding the init args:

```shell
didc encode -d ../../../rosetta-api/icrc1/index-ng/index-ng.did -t '(opt IndexArg)' '(opt variant { Init = record { ledger_id = principal "ss2fx-dyaaa-aaaar-qacoq-cai" } })' | xxd -r -p > index_arg.bin
```

Installing the canister:

```shell
../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id s3zol-vqaaa-aaaar-qacpa-cai \
    --mode install \
    --wasm-module-path ./ic-icrc1-index-ng-u256.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg index_arg.bin \
    --summary-file ./index_proposal.md
```
