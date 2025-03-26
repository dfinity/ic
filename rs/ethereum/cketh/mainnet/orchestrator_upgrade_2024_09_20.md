# Proposal to upgrade the ledger suite orchestrator canister

Git hash: `d4ee25b0865e89d3eaac13a60f0016d5e3296b31`

New compressed Wasm hash: `61a422257859c91ba01bb082c6daaae986a5ca7afcd9d0293dc9bc199e31c8c4`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/132131

---

## Motivation

1. Let the ckETH ledger suite be managed by the ledger suite orchestrator.
2. Upgrade all ledger suites managed by the orchestrator to the latest version to start the migration towards stable memory.

## Upgrade args

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "d4ee25b0865e89d3eaac13a60f0016d5e3296b31"; ledger_compressed_wasm_hash = opt "e6072806ae22868ee09c07923d093b1b0b687dba540d22cfc1e1a5392bfcca46"; index_compressed_wasm_hash = opt "de250f08dc7e699144b73514f55fbbb3a3f8cd97abf0f7ae31d9fb7494f55234"; archive_compressed_wasm_hash = opt "e9c7cad647ede2ea2942572f337bd27d0839dd06c5e2c7f03591226acb10a9fb"; manage_ledger_suites = opt vec { record { token_symbol = "ckETH"; ledger = record { canister_id = principal "ss2fx-dyaaa-aaaar-qacoq-cai"; installed_wasm_hash = "8457289d3b3179aa83977ea21bfa2fc85e402e1f64101ecb56a4b963ed33a1e6"}; index = record { canister_id = principal "s3zol-vqaaa-aaaar-qacpa-cai"; installed_wasm_hash = "eb3096906bf9a43996d2ca9ca9bfec333a402612f132876c8ed1b01b9844112a"}; archives = opt vec { principal "xob7s-iqaaa-aaaar-qacra-cai" }}}}})'
```

## Release Notes

### Orchestrator
```
git log --format='%C(auto) %h %s' 667a6bd3bc08c58535b8b63bfebc01dba89c0704..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/ethereum/ledger-suite-orchestrator
48f24e7e4 fix(ckerc20): bug in renaming field (#1429)
3c1524ed2 feat(ckerc20): Add already installed canisters to ledger suite orchestrator (#1312)
e16520fac chore(IDX): move container to ci dir (#1343)
4d09678d2 chore: sort rust derive traits (#1241)
d4c3bb26c chore: upgrade crates and use workspace version (#1207)
 ```

### Ledger

```
git log --format="%C(auto) %h %s" 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/rosetta-api/icrc1/ledger
643e4fb30c fix(ICRC-ledger): FI-1482: read magic bytes to determine if memory manager is used (#1448)
e680d5b916 fix(ICRC-1 Ledger): add effective subaccount to ICRC-21 (#1405)
d323465e02 feat(ICRC-Ledger): add ability to read from memory manager in post_upgrade (#746)
4d09678d23 chore: sort rust derive traits (#1241)
68aed51e4b test(icrc_ledger): FI-1400: Add golden state ledger verification with ckBTC and ckETH workarounds (#721)
d4c3bb26c2 chore: upgrade crates and use workspace version (#1207)
92185b9664 test(ICRC_ledger): FI-1377: Check balances, allowances, blocks, metadata, and total supply between upgrades (#1082)
d71e09e83a chore: add decoding quota to http_request in SNS and ICRC1 canisters (#1101)
4e5d6322bb chore: add decoding quota to http_request in NNS canisters (#1060)
1fd18580db chore(ICP-Ledger): FI-1426: remove maximum number of accounts (#972)
dada69e8fa fix(ICRC-21): FI-1424: method not supported error message (#921)
ca24b5d66d chore: sort dependencies in Cargo.toml files (#828)
99813d3fa9 test(icrc_ledger): FI-1399: Add an InMemoryLedger for verifying ICRC ledger state (#719)
```

### Index

```
git log --format="%C(auto) %h %s" 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/rosetta-api/icrc1/index-ng
4d09678d23 chore: sort rust derive traits (#1241)
d4c3bb26c2 chore: upgrade crates and use workspace version (#1207)
d71e09e83a chore: add decoding quota to http_request in SNS and ICRC1 canisters (#1101)
1fd18580db chore(ICP-Ledger): FI-1426: remove maximum number of accounts (#972)
```

### Archive

```
git log --format="%C(auto) %h %s" 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/rosetta-api/icrc1/archive
4d09678d23 chore: sort rust derive traits (#1241)
d71e09e83a chore: add decoding quota to http_request in SNS and ICRC1 canisters (#1101)
```


## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
