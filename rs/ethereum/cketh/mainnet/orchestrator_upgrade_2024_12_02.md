# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2190613d3b5bcd9b74c382b22d151580b8ac271a`

New compressed Wasm hash: `57b63457b2721e7fe649fe418576236f7a5ca49669f1acae208880a84011f167`

Upgrade args hash: `5c2d86b8a8c058dd11537a44c6a9a14f6d31187aa4b1bca5c04b317837ee2c44`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/133797

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest version ([ledger-suite-icrc-2024-11-28](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2024-11-28)) to continue the migration towards stable memory.


## Upgrade args

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "2190613d3b5bcd9b74c382b22d151580b8ac271a"; ledger_compressed_wasm_hash = opt "9637743e1215a4db376a62ee807a0986faf20833be2b332df09b3d5dbdd7339e"; index_compressed_wasm_hash = opt "d615ea66e7ec7e39a3912889ffabfabb9b6f200584b9656789c3578fae1afac7"; archive_compressed_wasm_hash = opt "2d25f7831894100d48aa9043c65e87c293487523f0958c15760027d004fbbda9"}})' | xxd -r -p | sha256sum
```

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ethereum/ledger-suite-orchestrator
3e0cf89b2 test(IDX): depend on the universal canister at run-time instead of at build-time (#2502)
aa7a0739d refactor(cross-chain): rename metrics related to memory (#2372)
15d752c5d chore: avoid reexports from StateMachine tests (#2370)
989230c65 test(ckerc20): Speed-up integration tests of ledger suite orchestrator (#2135)
a25a338b9 test(IDX): don't run tests that take longer than 5 mins on PRs (#2017)
0a5351777 chore: upgrade core crates and use workspace version (#2111)
 ```

### Ledger Suite

The commit used `2190613d3b5bcd9b74c382b22d151580b8ac271a` corresponds to the [ICRC Ledger Suite release 2024-11-28](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2024-11-28).

#### Ledger

```
git log --format="%C(auto) %h %s" e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ledger_suite/icrc1/ledger
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

#### Index

```
git log --format="%C(auto) %h %s" e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ledger_suite/icrc1/index-ng
2b21236228 refactor(ICP_ledger): FI-1570: Rename ledger suite memory-related metrics (#2545)
ee1006503b test(ICRC_index_ng): FI-1519: Add test for ICRC index-ng sync with ledger with various intervals (#2313)
15d752c5dd chore: avoid reexports from StateMachine tests (#2370)
d361dd6923 feat: Update cycles cost for compute (#2308)
07cf5773d4 feat(Index-ng): FI-1389: Disallow upgrading ICRC index-ng from u64 to u256 or vice versa (#1987)
03dd6ee6de fix(Ledger-Suite): renamed state machine tests (#2014)
```

#### Archive

```
git log --format="%C(auto) %h %s" e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ledger_suite/icrc1/archive
2b21236228 refactor(ICP_ledger): FI-1570: Rename ledger suite memory-related metrics (#2545)
15d752c5dd chore: avoid reexports from StateMachine tests (#2370)
```



## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
