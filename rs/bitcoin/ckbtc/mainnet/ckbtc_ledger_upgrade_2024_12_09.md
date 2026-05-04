# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2190613d3b5bcd9b74c382b22d151580b8ac271a`

New compressed Wasm hash: `25071c2c55ad4571293e00d8e277f442aec7aed88109743ac52df3125209ff45`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/133824

---

## Motivation

Upgrade the ckBTC ledger canister to the latest version ([ledger-suite-icrc-2024-11-28](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2024-11-28)) to continue the migration towards stable memory.


## Upgrade args

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
cd rs/ledger_suite/icrc1/ledger
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ledger_suite/icrc1/ledger
8d726cc67a feat(ICRC-ledger): FI-1437: Implement V3 for ICRC ledger - migrate allowances to stable structures (#1513)
f68da752b5 feat(ICRC-Rosetta): updated rosetta to support icrc3 standard (#2607)
7c718f95a4 chore(Ledger_suite): FI-1573: Update the ledger suite canister git revs and module hashes (#2547)
593f0cd19c chore(FI): Cleanup unused dependencies (#2628)
6da35b9432 refactor: [FI-1531] Support ICP blocks and accounts in InMemoryLedger (#2497)
2b21236228 refactor(ICP_ledger): FI-1570: Rename ledger suite memory-related metrics (#2545)
3e0cf89b23 test(IDX): depend on the universal canister at run-time instead of at build-time (#2502)
b811de98a7 feat(ICP-Ledger): FI-1436: Implement V2 for ICP ledger - use memory manager during upgrade (#1969)
6971fee041 test(ICRC_ledger): FI-1542: Add fee collector test for icrc3_get_blocks (#2181)
588ad7a46b chore: upgrade rust version to 1.82 (#2137)
03dd6ee6de fix(Ledger-Suite): renamed state machine tests (#2014)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
