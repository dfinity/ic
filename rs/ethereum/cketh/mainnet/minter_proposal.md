# Proposal to Install the ckETH Minter Canister

Git hash: `5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576`

New compressed Wasm hash: `e0167373ddd503c06a93faa2dac2d8da8118894a2552fc811186e31d5c49f27e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

---

## Motivation

This proposal install the mainnet ckETH minter to the governance-controlled canister ID [`sv3dd-oaaaa-aaaar-qacoa-cai`](https://dashboard.internetcomputer.org/canister/sv3dd-oaaaa-aaaar-qacoa-cai) on subnet [`pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`](https://dashboard.internetcomputer.org/subnet/pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae).

## Install args

```
git fetch
git checkout 5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant { InitArg = record { ethereum_network = variant { Mainnet }; ecdsa_key_name = "key_1"; ethereum_contract_address = opt "0x7574eB42cA208A4f6960ECCAfDF186D627dCC175"; ledger_id = principal "ss2fx-dyaaa-aaaar-qacoq-cai"; ethereum_block_height = variant { Finalized }; minimum_withdrawal_amount = 30_000_000_000_000_000; next_transaction_nonce = 0; last_scraped_block_number = 18676637 } })'
```

* [ss2fx-dyaaa-aaaar-qacoq-cai](https://dashboard.internetcomputer.org/canister/ss2fx-dyaaa-aaaar-qacoq-cai) is the governance-controlled canister ID that will become the ckETH ledger.
* The minimum withdrawal amount of 0.03 ETH (30_000_000_000_000_000 wei) is a rough equivalent of 60 USD as of November 30, 2023.
* 18676637 is the Ethereum block in which the [helper contract](https://etherscan.io/address/0x7574eB42cA208A4f6960ECCAfDF186D627dCC175) was installed.

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```

