# Proposal to upgrade the ledger suite orchestrator canister

Git hash: `3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d`

New compressed Wasm hash: `ccda8966249bc7d89f14968a242d6fb2c33d2363336303ec4f12977cab74c6f7`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/131388

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest version to add support for the [ICRC-21: Canister Call Consent Messages](https://github.com/dfinity/wg-identity-authentication/blob/fd846030109710cab67d9381485a73db424f2b07/topics/ICRC-21/icrc_21_consent_msg.md) standard.

## Upgrade args

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d"; ledger_compressed_wasm_hash = opt "8457289d3b3179aa83977ea21bfa2fc85e402e1f64101ecb56a4b963ed33a1e6"; index_compressed_wasm_hash = opt "eb3096906bf9a43996d2ca9ca9bfec333a402612f132876c8ed1b01b9844112a"; archive_compressed_wasm_hash = opt "5bd1f69540bd48493018e13bb5ad25aba75d59403ced1d5958bf718147228d31"}})'
```

## Release Notes

### Orchestrator
No changes since last version (`de29a1a55b589428d173b31cdb8cec0923245657`).

```
git log --format="%C(auto) %h %s" de29a1a55b589428d173b31cdb8cec0923245657..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/ethereum/ledger-suite-orchestrator
 ```

### Ledger

```
git log --format="%C(auto) %h %s" de29a1a55b589428d173b31cdb8cec0923245657..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/rosetta-api/icrc1/ledger
f2f408333a test(ICRC-Ledger): FI-1377: Add tests for upgrading ICRC ledger with WASMs with different token types (#388)
14836b59da chore(ICP/ICRC-Ledger): FI-1373: refactor approvals library to allow using regular and stable allowance storage (#382)
33187dbe82 fix(ICRC-21): FI-1386: add e 8 s to icrc 21 (#340)
```

### Index

```
git log --format="%C(auto) %h %s" de29a1a55b589428d173b31cdb8cec0923245657..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/rosetta-api/icrc1/index-ng
b4be567dc0 chore: Bump rust version to 1.80 (#642)
eec6107faf chore: remove obsolete cost scaling feature flag (#502)
```

### Archive

No changes since last version (`de29a1a55b589428d173b31cdb8cec0923245657`).
```
git log --format="%C(auto) %h %s" de29a1a55b589428d173b31cdb8cec0923245657..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/rosetta-api/icrc1/archive
```



## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
