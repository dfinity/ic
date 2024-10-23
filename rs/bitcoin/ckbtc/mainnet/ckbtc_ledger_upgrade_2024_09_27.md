# Proposal to upgrade the ckBTC ledger canister

Git hash: `d4ee25b0865e89d3eaac13a60f0016d5e3296b31`

New compressed Wasm hash: `a170bfdce5d66e751a3cc03747cb0f06b450af500e75e15976ec08a3f5691f4c`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/132129

---

## Motivation
Upgrade the ckBTC ledger canister to the latest version to start the migration towards stable memory.

## Upgrade args

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
cd rs/rosetta-api/icrc1/ledger
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/rosetta-api/icrc1/ledger
643e4fb30 fix(ICRC-ledger): FI-1482: read magic bytes to determine if memory manager is used (#1448)
e680d5b91 fix(ICRC-1 Ledger): add effective subaccount to ICRC-21 (#1405)
d323465e0 feat(ICRC-Ledger): add ability to read from memory manager in post_upgrade (#746)
4d09678d2 chore: sort rust derive traits (#1241)
68aed51e4 test(icrc_ledger): FI-1400: Add golden state ledger verification with ckBTC and ckETH workarounds (#721)
d4c3bb26c chore: upgrade crates and use workspace version (#1207)
92185b966 test(ICRC_ledger): FI-1377: Check balances, allowances, blocks, metadata, and total supply between upgrades (#1082)
d71e09e83 chore: add decoding quota to http_request in SNS and ICRC1 canisters (#1101)
4e5d6322b chore: add decoding quota to http_request in NNS canisters (#1060)
1fd18580d chore(ICP-Ledger): FI-1426: remove maximum number of accounts (#972)
dada69e8f fix(ICRC-21): FI-1424: method not supported error message (#921)
ca24b5d66 chore: sort dependencies in Cargo.toml files (#828)
99813d3fa test(icrc_ledger): FI-1399: Add an InMemoryLedger for verifying ICRC ledger state (#719)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
