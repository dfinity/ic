# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2190613d3b5bcd9b74c382b22d151580b8ac271a`

New compressed Wasm hash: `57b63457b2721e7fe649fe418576236f7a5ca49669f1acae208880a84011f167`

Upgrade args hash: `5c2d86b8a8c058dd11537a44c6a9a14f6d31187aa4b1bca5c04b317837ee2c44`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/133797

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Upgrade args

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "2190613d3b5bcd9b74c382b22d151580b8ac271a"; ledger_compressed_wasm_hash = opt "9637743e1215a4db376a62ee807a0986faf20833be2b332df09b3d5dbdd7339e"; index_compressed_wasm_hash = opt "d615ea66e7ec7e39a3912889ffabfabb9b6f200584b9656789c3578fae1afac7"; archive_compressed_wasm_hash = opt "2d25f7831894100d48aa9043c65e87c293487523f0958c15760027d004fbbda9"}})' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ethereum/ledger-suite-orchestrator
3e0cf89b2 test(IDX): depend on the universal canister at run-time instead of at build-time (#2502)
aa7a0739d refactor(cross-chain): rename metrics related to memory (#2372)
15d752c5d chore: avoid reexports from StateMachine tests (#2370)
989230c65 test(ckerc20): Speed-up integration tests of ledger suite orchestrator (#2135)
a25a338b9 test(IDX): don't run tests that take longer than 5 mins on PRs (#2017)
0a5351777 chore: upgrade core crates and use workspace version (#2111)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
