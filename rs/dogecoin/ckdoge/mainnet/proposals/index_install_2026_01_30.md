# Proposal to install the ckDOGE index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e446c64d99a97e38166be23ff2bfade997d15ff7`

New compressed Wasm hash: `8df72887ab235f4533ee613b1bc7293ec8d62c866525b1425934cf992ef894a7`

Install args hash: `dd884f4ad2404d6cbae6d121d389818899a529fda231e4511f7727a135c4d2a7`

Target canister: `ecnej-3aaaa-aaaar-qb3wq-cai`

---

## Motivation

This proposal installs the mainnet ckDOGE index to the governance-controlled canister ID [`ecnej-3aaaa-aaaar-qb3wq-cai`](https://dashboard.internetcomputer.org/canister/ecnej-3aaaa-aaaar-qb3wq-cai) on subnet [`pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`](https://dashboard.internetcomputer.org/subnet/pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae).
This is the U256 version of the index from the ledger suite release [ledger-suite-icrc-2025-10-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-10-27).


## Install args

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
didc encode -d rs/ledger_suite/icrc1/index-ng/index-ng.did -t '(opt IndexArg)' '(opt variant { Init = record { ledger_id = principal "efmc5-wyaaa-aaaar-qb3wa-cai" } })' | xxd -r -p | sha256sum
```

About the initialization arguments:

* `ledger_id`: The governance-controlled ckDOGE ledger is [`efmc5-wyaaa-aaaar-qb3wa-cai`](https://dashboard.internetcomputer.org/canister/efmc5-wyaaa-aaaar-qb3wa-cai).

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
```
