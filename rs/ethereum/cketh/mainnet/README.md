# ckETH Mainnet Deployment
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
didc encode -d ../../../ledger_suite/icrc1/ledger/ledger.did -t '(LedgerArg)' '(variant { Init = record { minting_account = record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai" }; fee_collector_account = opt record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai"; subaccount = opt blob "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0f\ee"; }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 2_000_000_000_000; token_symbol = "ckETH"; token_name = "ckETH"; feature_flags = opt record { icrc2 = true }; metadata = vec { record { "icrc1:logo"; variant { Text = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45NEMzNy4zMDg3IDEzMy44NjcgMTIuMTMzIDEwOC42OTEgMTAuMDYwNSA3Ny4yMDUySDE2LjM4MzdaIiBmaWxsPSJ1cmwoI3BhaW50MF9saW5lYXJfMTEwXzU4NikiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02OC43NjQ2IDE2LjM1MzRDNDAuNzYzOCAxOC40MDM2IDE4LjQwMzcgNDAuNzYzNyAxNi4zNTM1IDY4Ljc2NDZMMTAuMDMwMyA2OC43NjQ2QzEyLjEwMjcgMzcuMjc4NCAzNy4yNzg1IDEyLjEwMjYgNjguNzY0NiAxMC4wMzAyTDY4Ljc2NDYgMTYuMzUzNFoiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMjkuNjE2IDY4LjczNDNDMTI3LjU2NiA0MC43MzM0IDEwNS4yMDYgMTguMzczMyA3Ny4yMDUxIDE2LjMyMzFMNzcuMjA1MSA5Ljk5OTk4QzEwOC42OTEgMTIuMDcyNCAxMzMuODY3IDM3LjI0ODEgMTM1LjkzOSA2OC43MzQzTDEyOS42MTYgNjguNzM0M1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl8xMTBfNTg2KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03My4xOTA0IDMxVjYxLjY4MThMOTkuMTIzIDczLjI2OTZMNzMuMTkwNCAzMVoiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAzMUw0Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA2MS42ODE4VjMxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczLjE5MDQgOTMuMTUyM1YxMTRMOTkuMTQwMyA3OC4wOTg0TDczLjE5MDQgOTMuMTUyM1oiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAxMTRWOTMuMTQ4OEw0Ny4yNTQ0IDc4LjA5ODRMNzMuMTkwNCAxMTRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNNzMuMTkwNCA4OC4zMjY5TDk5LjEyMyA3My4yNjk2TDczLjE5MDQgNjEuNjg4N1Y4OC4zMjY5WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC4yIi8+CjxwYXRoIGQ9Ik00Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA4OC4zMjY5VjYxLjY4ODdMNDcuMjU0NCA3My4yNjk2WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC42Ii8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU4NiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTg2IiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==" }}}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 100_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "r7inp-6aaaa-aaaaa-aaabq-cai" } } })' | xxd -r -p > ledger_arg.bin
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
    --mode reinstall \
    --wasm-module-path ./ic-icrc1-ledger-u256.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg ledger_arg.bin \
    --summary-file ./ledger_proposal.md
```

Submitting an upgrade proposal:

```shell
didc encode -d ../../../ledger_suite/icrc1/ledger/ledger.did -t '(LedgerArg)' '(variant {Upgrade})' | xxd -r -p > ledger_arg.bin
```

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
    --canister-id ss2fx-dyaaa-aaaar-qacoq-cai \
    --mode upgrade \
    --wasm-module-path ./ic-icrc1-ledger-u256.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg ledger_arg.bin \
    --summary-file ./ledger_upgrade_yyyy_mm_dd.md
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

Submitting an upgrade proposal:

```shell
didc encode -d ../minter/cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {} })' | xxd -r -p > minter_arg.bin
```

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
    --canister-id sv3dd-oaaaa-aaaar-qacoa-cai \
    --mode upgrade \
    --wasm-module-path ./ic-cketh-minter.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg minter_arg.bin \
    --summary-file ./minter_upgrade_yyyy_mm_dd.md
```


## Installing the [index](https://dashboard.internetcomputer.org/canister/s3zol-vqaaa-aaaar-qacpa-cai)


Encoding the init args:

```shell
didc encode -d ../../../ledger_suite/icrc1/index-ng/index-ng.did -t '(opt IndexArg)' '(opt variant { Init = record { ledger_id = principal "ss2fx-dyaaa-aaaar-qacoq-cai" } })' | xxd -r -p > index_arg.bin
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

## Deployment of ckERC20

Tasks:
1. [x] Create empty canister for the orchestrator, see `vxkom-oyaaa-aaaar-qafda-cai`.
2. [x] Change controller of the orchestrator to the NNS root `r7inp-6aaaa-aaaaa-aaabq-cai` and self `vxkom-oyaaa-aaaar-qafda-cai`.
3. [x] Install the orchestrator canister wasm via NNS proposal, see the [proposal](orchestrator_install_2024_05_10).
4. [x] Deploy the ckERC20 deposit helper smart contract on Ethereum mainnet.
5. [x] Upgrade the minter canister via NNS proposal to support ckERC20, see the [proposal](minter_upgrade_2024_05_10).
6. [x] Add at least 500T cycles to the orchestrator canister `vxkom-oyaaa-aaaar-qafda-cai`.
7. [x] Add ckUSDC by upgrading the orchestrator via NNS proposal, see the [proposal](orchestrator_upgrade_2024_05_19).

Step 3 and (4,5) could happen in any order (first 3, then (4.5); or first (4,5), then 3). It's crucial that the last step happens after step 5 so that the minter is aware of the orchestrator, which will notify the minter when a new token is added.

## Test the proposals on a testnet

To test the proposals with a testnet that uses the same canister IDs as in the proposals we need:
* dynamic testnet with an API boundary node and an HTTP Gateway (`ic-gateway`)
* 36 application subnets with one node each. This ensures that a high subnet index like the one of the fiduciary subnet is part of the topology.

### Spin up the dynamic testnet

The simplest is to tweak the setup from [small](https://sourcegraph.com/github.com/dfinity/ic@7313a15e21d8fb06fa119ef3ab9371da47c2cddc/-/blob/rs/tests/idx/testnets/small.rs?L62)
```rust
pub fn setup(env: TestEnv) {
    let mut ic = InternetComputer::new().add_subnet(Subnet::new(SubnetType::System).add_nodes(1));
    for _ in 0..36 {
        ic = ic.add_subnet(Subnet::new(SubnetType::Application).add_nodes(1));
    }
    ic.with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
}
```

and then spin up the dynamic testnet:
```shell
./ci/container/container-run.sh
ict testnet create small --output-dir=./small -- --test_tmpdir=./small
```

Once the testnet is up and running, extract the external url of the HTTP Gateway (`ic-gateway`) from the logs, which should have the following format `https://ic<x>.farm.dfinity.systems`. In the following we will use `https://ic1.farm.dfinity.systems`.

### Create the canisters

For each canister:
1. Creates an empty canister with the required ID.
2. Reset the controller of the created canister to the NNS root (`r7inp-6aaaa-aaaaa-aaabq-cai`). This is needed because we will install the wasm via proposals controlled by the NNS governance canister.

For the ledger canister:
```shell
dfx --provisional-create-canister-effective-canister-id ss2fx-dyaaa-aaaar-qacoq-cai  canister --network "https://ic1.farm.dfinity.systems" create ledger --specified-id ss2fx-dyaaa-aaaar-qacoq-cai

dfx --identity default canister --network testnet update-settings --set-controller r7inp-6aaaa-aaaaa-aaabq-cai ledger
````

For the index canister:
```shell
dfx --provisional-create-canister-effective-canister-id s3zol-vqaaa-aaaar-qacpa-cai  canister --network "https://ic1.farm.dfinity.systems" create index --specified-id s3zol-vqaaa-aaaar-qacpa-cai

dfx --identity default canister --network testnet update-settings --set-controller r7inp-6aaaa-aaaaa-aaabq-cai index
```

For the minter canister:
```shell
dfx --provisional-create-canister-effective-canister-id sv3dd-oaaaa-aaaar-qacoa-cai  canister --network "https://ic1.farm.dfinity.systems" create minter --specified-id sv3dd-oaaaa-aaaar-qacoa-cai
dfx --identity default canister --network testnet update-settings --set-controller r7inp-6aaaa-aaaaa-aaabq-cai minter
```

You can check that the controller has been reset with:
```shell
dfx --identity default canister --network testnet info minter

Controllers: r7inp-6aaaa-aaaaa-aaabq-cai
Module None
```

### Submit the proposals

To submit proposals we need a neuron. All dynamic testnet come up with a pre-loaded bunch of neurons, we will use [`TEST_NEURON_1_ID`](https://sourcegraph.com/github.com/dfinity/ic@3f9f6b24d0bd25fee09e85ab32d68ec5825affc2/-/blob/rs/nns/test_utils/src/ids.rs?L8) which has value `449479075714955186` and whose keypair is defined [here](https://sourcegraph.com/github.com/dfinity/ic@3f9f6b24d0bd25fee09e85ab32d68ec5825affc2/-/blob/rs/nervous_system/common/test_keys/src/lib.rs?L14). Store the secret key in a new file  `./TEST_NEURON_1.pem`:
```
-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIHS9H6NEjE5Leh3oMjTXcESspk8fgapoDI/xCBZV
fnKNoSMDIQD2HfCf/GkgYxwyFO2lbjCEcHa1yNj1HO8kGMftgRS8lA==
-----END PRIVATE KEY-----
```

For the ledger
```shell
 ic-admin --nns-url "https://ic1.farm.dfinity.systems" --secret-key-pem ./TEST_NEURON_1.pem propose-to-change-nns-canister --proposer 449479075714955186 --canister-id ss2fx-dyaaa-aaaar-qacoq-cai --mode install --wasm-module-path ic-icrc1-ledger-u256.wasm.gz --wasm-module-sha256 3148f7a9f1b0ee39262c8abe3b08813480cf78551eee5a60ab1cf38433b5d9b0 --arg ledger_arg.bin --summary-file ledger_proposal.md
```

For the index canister
```shell
ic-admin --nns-url "https://ic1.farm.dfinity.systems" --secret-key-pem ./TEST_NEURON_1.pem propose-to-change-nns-canister --proposer 449479075714955186 --canister-id s3zol-vqaaa-aaaar-qacpa-cai --mode install --wasm-module-path ic-icrc1-index-ng-u256.wasm.gz --wasm-module-sha256 3a6d39b5e94cdef5203bca62720e75a28cd071ff434d22b9746403ac7ae59614 --arg index_arg2.bin --summary-file index_proposal.md
```

For the minter
```shell
ic-admin --nns-url "https://ic1.farm.dfinity.systems" --secret-key-pem ./TEST_NEURON_1.pem propose-to-change-nns-canister --proposer 449479075714955186 --canister-id sv3dd-oaaaa-aaaar-qacoa-cai --mode install --wasm-module-path ic-cketh-minter.wasm.gz --wasm-module-sha256 e0167373ddd503c06a93faa2dac2d8da8118894a2552fc811186e31d5c49f27e --arg minter_arg.bin --summary-file minter_proposal.md
```

As soon as each proposal is submitted, it will be executed since `TEST_NEURON_1_ID` has the majority of the voting power.
Once executed, the canisters should be up and running and could for example be called directly by `dfx`.
It's also a good idea to check the Kibana logs to make sure that the canisters were installed as expected.
In particular, any error in the init args will be reported in the Kibana logs, similar to the following:
```
Finished executing install_code message on canister CanisterId(s3zol-vqaaa-aaaar-qacpa-cai) after 0.594825038 with error: Hypervisor(CanisterId(s3zol-vqaaa-aaaar-qacpa-cai), CalledTrap("Index initialization must take in input an InitArg argument")), instructions consumed 2583657505
```

### Bonus: Activate tECDSA and HTTP outcalls

From the Kibana logs, find out on which subnet the minter was installed. In the following commands we use `kji32-q2q2c-iclry-dfqpa-jqoku-g7ib3-fceyl-mgulh-szuz7-e7ajs-eqe`.

```shell
 ic-admin --nns-url  "https://ic1.farm.dfinity.systems" --secret-key-pem ./TEST_NEURON_1.pem propose-to-update-subnet --proposer 449479075714955186 --features "http_requests" --subnet kji32-q2q2c-iclry-dfqpa-jqoku-g7ib3-fceyl-mgulh-szuz7-e7ajs-eqe --summary "Enable the HTTPS outcalls feature"
```

If this works, then the minter should be able to retrieve the current transaction fees:
```shell
dfx --identity default canister --network "https://ic1.farm.dfinity.systems" call minter eip_1559_transaction_price
```

```shell
 ic-admin --nns-url "https://ic1.farm.dfinity.systems" --secret-key-pem ./TEST_NEURON_1.pem propose-to-update-subnet --proposer 449479075714955186 --ecdsa-keys-to-generate Secp256k1:key_1 --subnet kji32-q2q2c-iclry-dfqpa-jqoku-g7ib3-fceyl-mgulh-szuz7-e7ajs-eqe --summary "Generate ECDSA key"
```

```shell
ic-admin --nns-url "https://ic1.farm.dfinity.systems" --secret-key-pem ./TEST_NEURON_1.pem propose-to-update-subnet --proposer 449479075714955186 --ecdsa-key-signing-enable Secp256k1:key_1 --subnet kji32-q2q2c-iclry-dfqpa-jqoku-g7ib3-fceyl-mgulh-szuz7-e7ajs-eqe --summary "Enable ECDSA key signing"
```

After a while it should be possible to retrieve the minter's address on Ethereum (which is derived from the minter tECDSA public key):
```shell
dfx --identity default canister --network "https://ic1.farm.dfinity.systems" call minter minter_address
```
