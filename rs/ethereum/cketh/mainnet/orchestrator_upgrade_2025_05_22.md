# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26`

New compressed Wasm hash: `3658ac0dc18bd0dff2e9e4ece141ce4b8bb280ea4bcaee276975005744a5b63b`

Upgrade args hash: `9cab12984fada0ac2207b2f7f7d46dd97926f5ed8f01183bc7fc8959d714cabf`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/136364

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest
version ([ledger-suite-icrc-2025-05-22](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-05-22)).

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' 512cf412f33d430b79f42330518166d14fc6884e..fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26 -- rs/ethereum/ledger-suite-orchestrator
1f71efe574 feat(ICRC-Ledger): FI-1546: Implement the ICRC-103 standard (#4840)
b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
a86da36995 refactor(cross-chain): use public crate ic-management-canister-types (#4903)
c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
 ```

### Ledger Suite

The commit used `fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26` corresponds to
the [ICRC Ledger Suite release 2025-05-22](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-05-22).

#### Ledger

```
git log --format="%C(auto) %h %s" 512cf412f33d430b79f42330518166d14fc6884e..fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26 -- rs/ledger_suite/icrc1/ledger
 1f71efe574 feat(ICRC-Ledger): FI-1546: Implement the ICRC-103 standard (#4840)
 33e44adbae chore(Ledgers): FI-1731: Update ledger suite mainnet canisters json (#5146)
 92051ebe9d test(ICRC_Ledger): FI-1732: Re-enable test_icrc1_test_suite test (#5151)
 b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
 830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
 2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
 f68a58fab6 chore: update Rust to 1.85.1 (#4340)
 3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
 b0cbc5c187 feat(ICRC_Ledger): FI-1660: Forbid setting fee collector to minting account (#3800)
 c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
```

#### Index

```
git log --format="%C(auto) %h %s" 512cf412f33d430b79f42330518166d14fc6884e..fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26 -- rs/ledger_suite/icrc1/index-ng
 b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
 830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
 2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
 3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
 ecb620b09d chore(ICRC_Index_NG): FI-1594: Change the type of fee and amount to Tokens (#3368)
 c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
```

#### Archive

```
git log --format="%C(auto) %h %s" 512cf412f33d430b79f42330518166d14fc6884e..fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26 -- rs/ledger_suite/icrc1/archive
 b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
 830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
 2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
 3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
 c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
```

## Upgrade args

```
git fetch
git checkout fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26"; ledger_compressed_wasm_hash = opt "adc3e1d2e35e000cff58ee8435a21773b3e5b7c8a7dd96244000996cb8dea9da"; index_compressed_wasm_hash = opt "d652c0c6f80174fc00a68231eecca9eb4e593294d3bf81ea6895860d8ef9d630"; archive_compressed_wasm_hash = opt "0f41d25daacee1a1e283c74f4cf665d62d3e5e811ce70376859bb9f918966688"}})' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hashes of the gzipped WASMs for the ledger, index and archive match the proposed hashes in the upgrade
arguments.

```
git fetch
git checkout fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```