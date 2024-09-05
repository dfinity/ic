# Proposal to upgrade the ledger suite orchestrator canister

Git hash: `de29a1a55b589428d173b31cdb8cec0923245657`

New compressed Wasm hash: `81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/131053

---

## Motivation

This upgrades the ledger suite orchestrator and all managed ledger suites to the latest version.

The motivation to upgrade the orchestrator are mainly the following points:
1. Add logic to make upgrade of managed canisters possible.
2. Simplify upgrade arguments to add new ckERC20 tokens.

The motivation to upgrade all ledger suites is as follows:
1. Add various metrics to the ledger (number of instructions used during upgrades and the number of approvals).

Upgrading the corresponding index and archive canisters of all managed ledger suites, while not strictly necessary, simplifies version management by ensuring that all canisters use the code from the same git commit.


## Upgrade args

```
git fetch
git checkout de29a1a55b589428d173b31cdb8cec0923245657
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "de29a1a55b589428d173b31cdb8cec0923245657"; ledger_compressed_wasm_hash = opt "9495d67c6e9ab4cec3740d68fa0a103dbcfd788d978f4cb58308d847d59e635b"; index_compressed_wasm_hash = opt "12612d5b2565b018a01fa5007c1de54c750c74dbd485f1ef31d71d689177fa86"; archive_compressed_wasm_hash = opt "080d7f03f18ca1e1804626b2cefe06f732a01f64f7d77e1a2c6bfea5a4b4baa1"}})'
```

## Release Notes

### Orchestrator

```
git log --format="%C(auto) %h %s" 4472b0064d347a88649beb526214fde204f906fb..de29a1a55b589428d173b31cdb8cec0923245657 -- rs/ethereum/ledger-suite-orchestrator
ce468ecac feat(ckerc20): Simplify adding new ckERC20 token (II) (#365)
ff90a5234 feat(ckerc20): Simplify adding new ckERC20 token
576bb8d17 chore: add buildifier sort comment to Bazel files
f609ec05a feat(PocketIC): IC mainnet-like ECDSA support in PocketIC
b1bf27ea4 docs(ckerc20): Fix the `git_commit_hash` in the ckERC20 proposal example (credit to @en)
4ba9c26ea Merge branch 'gdemay/XC-134-icrc3_get_archives' into 'master'
85af825dc refactor(ckerc20):  use `icrc3_get_archives` to discover archives
6d5977563 Merge branch 'gdemay/XC-133-guard-against-panic' into 'master'
a39d075bb fix(ckerc20): ensure ledger suite orchestrator tasks are rescheduled with a guard
25b47e040 docs(ckerc20): Explain how to add a new ckERC20 token
a5c8d79ad feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
0beae738b build(ckerc20): use `long` timeout for ledger suite orchestrator integration tests
035d212c0 Merge branch 'gdemay/XC-30-discover-archives-after-ledger-upgrade' into 'master'
4ee978a47 feat(ckerc20): Discover archives before upgrading them
6d3364381 Merge branch 'gdemay/XC-112-add-archives-to-the-dashboard' into 'master'
63390cb31 feat(ckerc20): Add archives to ckERC20 ledger suite orchestrator dashboard
9b383f709 Merge branch 'gdemay/XC-53-orchestrator-doc' into 'master'
8ff67bb5c docs(ckerc20): document the ckERC20 ledger suite orchestrator
e73f59f99 feat(icrc1-index-ng): FI-1296: Make index-ng interval for retrieving blocks from the ledger configurable
59f44e8e1 test(ckerc20): Integration tests for upgrading managed canisters by the ledger suite orchestrator
fe70537ba Merge branch 'gdemay/XC-30-lso-upgrade' into 'master'
cb770703f feat(ckerc20): upgrade ledger suite managed by the orchestrator
94c25e4db Merge branch 'alex/testonly-canister-sig-test-utils' into 'master'
ce2222b6c build: CRP-2131 add testonly to crypto test utils and adjust the dependents
14a17a447 feat(ckerc20): Expose `canister_status` in ledger suite orchestrator
1bfe616ec feat: build Rust canisters with opt-level=3 by default
 ```

### Ledger

```
git log --format="%C(auto) %h %s" 4472b0064d347a88649beb526214fde204f906fb..de29a1a55b589428d173b31cdb8cec0923245657 -- rs/rosetta-api/icrc1/ledger
50aa8cfd64 feat(icrc_ledger): FI-1323: Add metric for instructions consumed during upgrade to ICP and ICRC ledgers
576bb8d173 chore: add buildifier sort comment to Bazel files
e219f993d9 chore(ICRC21): FI-1339: Icrc 21 markdown refinement
d95111e334 Merge branch 'gdemay/XC-92-canbench-icrc1-ledger-archive' into 'master'
b078dc9f8b test(ledger): Benchmarks ICRC ledger with archiving
fb4e5bdfed chore(RUN-931): Add doc links to HypervisorErrors
dd934bbdd6 test(ledger): Add `canbench` to ICRC1 ledger
e281f01a26 feat(icrc_ledger): FI-1316: Add a metric for the total number of transactions processed by the ICRC ledger
5a5fdb5895 feat(icrc_ledger): FI-1322: Add metrics for the number of spawned archives
a8a02bfa1b feat(ICRC-1 Ledger): add icrc21 to icrc1 ledger
f7fe40b7dd Merge branch 'mathias-FI-1310-add-heap-memory-usage-metric' into 'master'
0c16902ca1 feat(ledger_suite): FI-1310: Add total memory usage metrics for ledger, archive, and index canisters
63dba97cb6 feat(ICP-Ledger): icrc21 transfer from
180750e6b6 feat(ICP-Ledger): FI-1178: icrc21 approve
648a15656f feat(icrc_ledger): FI-1161: Add metric for number of approvals in the ICRC ledger
ed7f7c98c8 feat(ICP-Ledger): FI-1177: icrc1 transfer for icrc21 endpoint
ce2222b6c4 build: CRP-2131 add testonly to crypto test utils and adjust the dependents
1bfe616ec0 feat: build Rust canisters with opt-level=3 by default
```

### Index

```
git log --format="%C(auto) %h %s" 4472b0064d347a88649beb526214fde204f906fb..de29a1a55b589428d173b31cdb8cec0923245657 -- rs/rosetta-api/icrc1/index-ng
18243444a2 fix(ICRC-Index): FI-1382: remove comment on removing 0 balance accounts (#341)
576bb8d173 chore: add buildifier sort comment to Bazel files
f7fe40b7dd Merge branch 'mathias-FI-1310-add-heap-memory-usage-metric' into 'master'
0c16902ca1 feat(ledger_suite): FI-1310: Add total memory usage metrics for ledger, archive, and index canisters
a5c8d79ade feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
610ebf1b7d chore(ICRC1 index-ng): FI-1306: Extract index-ng tests into separate file and shorten runtimes
d557530aee chore(index-ng): FI-1296: Set index-ng integration test timeout to long
e73f59f998 feat(icrc1-index-ng): FI-1296: Make index-ng interval for retrieving blocks from the ledger configurable
1bfe616ec0 feat: build Rust canisters with opt-level=3 by default
```

### Archive

```
git log --format="%C(auto) %h %s" 4472b0064d347a88649beb526214fde204f906fb..de29a1a55b589428d173b31cdb8cec0923245657 -- rs/rosetta-api/icrc1/archive
576bb8d173 chore: add buildifier sort comment to Bazel files
f7fe40b7dd Merge branch 'mathias-FI-1310-add-heap-memory-usage-metric' into 'master'
0c16902ca1 feat(ledger_suite): FI-1310: Add total memory usage metrics for ledger, archive, and index canisters
a5c8d79ade feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
1bfe616ec0 feat: build Rust canisters with opt-level=3 by default
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout de29a1a55b589428d173b31cdb8cec0923245657
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout de29a1a55b589428d173b31cdb8cec0923245657
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
