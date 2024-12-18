# Proposal to upgrade the ledger suite orchestrator canister

Git hash: `7fbb84aad7188d1d5b3e17b170997c29d1598cb8`

New compressed Wasm hash: `9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/129750

---

## Motivation

This is a regular upgrade containing minor improvements adding in particular the ability for the ckERC20 ledger suite
orchestrator to upgrade managed canisters.

## Upgrade args

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant {UpgradeArg = record {}})'
```

## Release Notes

```
git log --format=%C(auto) %h %s 4472b0064d347a88649beb526214fde204f906fb..7fbb84aad7188d1d5b3e17b170997c29d1598cb8 -- rs/ethereum/ledger-suite-orchestrator
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

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
