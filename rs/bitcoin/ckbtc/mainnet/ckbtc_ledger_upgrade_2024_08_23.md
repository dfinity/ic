# Proposal to upgrade the ckBTC ledger canister

Git hash: `3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d`

New compressed Wasm hash: `e8942f56f9439b89b13bd8037f357126e24f1e7932cf03018243347505959fd4`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/126394

---

## Motivation
Upgrade the ckBTC ledger canister to the latest version to add support for the [ICRC-21: Canister Call Consent Messages](https://github.com/dfinity/wg-identity-authentication/blob/fd846030109710cab67d9381485a73db424f2b07/topics/ICRC-21/icrc_21_consent_msg.md) standard.


## Upgrade args

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
cd rs/rosetta-api/icrc1/ledger
didc encode '()'
```

## Release Notes

```
git log --format=%C(auto) %h %s 6a8e5fca2c6b4e12966638c444e994e204b42989..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/rosetta-api/icrc1/ledger
f2f408333 test(ICRC-Ledger): FI-1377: Add tests for upgrading ICRC ledger with WASMs with different token types (#388)
14836b59d chore(ICP/ICRC-Ledger): FI-1373: refactor approvals library to allow using regular and stable allowance storage (#382)
33187dbe8 fix(ICRC-21): FI-1386: add e 8 s to icrc 21 (#340)
50aa8cfd6 feat(icrc_ledger): FI-1323: Add metric for instructions consumed during upgrade to ICP and ICRC ledgers
576bb8d17 chore: add buildifier sort comment to Bazel files
e219f993d chore(ICRC21): FI-1339: Icrc 21 markdown refinement
d95111e33 Merge branch 'gdemay/XC-92-canbench-icrc1-ledger-archive' into 'master'
b078dc9f8 test(ledger): Benchmarks ICRC ledger with archiving
fb4e5bdfe chore(RUN-931): Add doc links to HypervisorErrors
dd934bbdd test(ledger): Add `canbench` to ICRC1 ledger
e281f01a2 feat(icrc_ledger): FI-1316: Add a metric for the total number of transactions processed by the ICRC ledger
5a5fdb589 feat(icrc_ledger): FI-1322: Add metrics for the number of spawned archives
a8a02bfa1 feat(ICRC-1 Ledger): add icrc21 to icrc1 ledger
f7fe40b7d Merge branch 'mathias-FI-1310-add-heap-memory-usage-metric' into 'master'
0c16902ca feat(ledger_suite): FI-1310: Add total memory usage metrics for ledger, archive, and index canisters
63dba97cb feat(ICP-Ledger): icrc21 transfer from
180750e6b feat(ICP-Ledger): FI-1178: icrc21 approve
648a15656 feat(icrc_ledger): FI-1161: Add metric for number of approvals in the ICRC ledger
ed7f7c98c feat(ICP-Ledger): FI-1177: icrc1 transfer for icrc21 endpoint
ce2222b6c build: CRP-2131 add testonly to crypto test utils and adjust the dependents
1bfe616ec feat: build Rust canisters with opt-level=3 by default
96d973666 chore(rosetta): FI-1253: Sort dependencies in BUILD.bazel and Cargo.toml files under rs/rosetta-api
7957dab20 chore: rules_rust 0.33.0 -> 0.42.1
e9475596c Merge branch 'FI-1194' into 'master'
97282de22 feat(icrc-index-ng): support ICRC-3
00e10d345 feat(ledger): Enable ICRC1 ledger to change archive options upon upgrades
f4ec28ce0 chore(icrc-ledger): add icrc3 to supported standards
cd9a2faeb feat(icrc-ledger): add icrc3_get_blocks
478571dfc fix: make time in StateMachine tests strictly monotone
c2c47c413 Merge branch 'dsharifi/async-trait-workspace-dep' into 'master'
66b0b363c chore: Move async-trait dependency to workspace
294584d7a feat(icrc-ledger): partial ICRC-3 support in the ICRC Ledger
f539c0545 chore: Bump rust version to 1.77.1
b412b7931 chore: Move `hex` dependency to workspace
1cc624107 Merge branch 'dsharifi/num-traits-workspace-dep' into 'master'
0fe5aff1e chore: Move num-traits dependency to workspace
6bfc3729e chore: Move anyhow dependencies to workspace
e1c1033c7 feat(sns): Enable upgrading the SNS Ledger suite to the latest canister versions
f3d614b6e chore: rename ic00_types to management_canister_types
170c5bd4b chore: bump Rust version to `1.76.0`
b669077b2 feat(icrc): Add more controllers to archive spawned by ledger
547698dbf feat(icrc_ledger): ICRC-2 always enabled
2c30c7ac8 feat(FI-1114): [ICRC Rosetta] Property based testing
85eb8611e Merge branch 'rumenov/cddk' into 'master'
c25c7462b build: cddl upgrade
fbcfbd5e3 feat(ckerc20): PoC for a ledger suite orchestrator canister
fa6adacec Merge branch 'mk/bazel_ic_test2' into 'master'
40db11f8e Chore: Move sandbox env declarations to a common place
a8f0d7f61 build: upgrade candid to 0.10
b835f6ebb chore: bump Rust version to 1.75
1bed24caa feat(FI-1069): [ICRC Rosetta] Use big uint for rosetta storage
04bd60ce4 test(icrc1_ledger): FI-1095: Adding tests to verify written ledger blocks
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
