# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e54d3fa34ded227c885d04e64505fa4b5d564743`

New compressed Wasm hash: `b72d9ce3a174b3f2a086cf60225177ae1b09036008e413592d0b17ad599a8614`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/133084

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest version to continue the migration towards stable memory.


## Upgrade args

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "e54d3fa34ded227c885d04e64505fa4b5d564743"; ledger_compressed_wasm_hash = opt "98a7b7391608dc4a554d6964bad24157b6aaf890a05bbaad3fcc92033d9c7b02"; index_compressed_wasm_hash = opt "07dd7a18d047ac41c37be9ea200dc1e0cbe4606bbc737d5dbb89f6e0a6e7450d"; archive_compressed_wasm_hash = opt "3ba6fee3ce3d311eef8df0220ac38a411802ee57c0d073847ef2cf3efa6c60ed"}})' | xxd -r -p | sha256sum
```

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' d4ee25b0865e89d3eaac13a60f0016d5e3296b31..e54d3fa34ded227c885d04e64505fa4b5d564743 -- rs/ethereum/ledger-suite-orchestrator
ee0d1f67e chore: drop run_until_completion from canister tests (#1899)
fcbc91f0a chore: update `ic-cdk` to 0.16.0 (#1868)
3bbabefb7 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
2f71ed9e8 chore(cketh): Publish `ic-ethereum-types` (#1723)
d66fdcb4c chore: bump rust version to 1.81 (#1645)
97b407839 chore(cketh): Proposal to upgrade all ledger suites (#1592)
 ```

### Ledger Suite

The code for the ledger, index and archive canisters was moved from `rs/rosetta-api/icrc1` to `rs/ledger_suite/icrc1` as part of `3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)`. For this reason, the release notes below include the git log output for both directories.

#### Ledger

```
git log --format="%C(auto) %h %s" d4ee25b0865e89d3eaac13a60f0016d5e3296b31..e54d3fa34ded227c885d04e64505fa4b5d564743 -- rs/rosetta-api/icrc1/ledger rs/ledger_suite/icrc1/ledger
44287b5f6b chore: Update mainnet-canisters.json (#2053)
b98f0feed2 feat(ICRC-ledger): FI-1532: Check for incompatible downgrade in ICRC ledger (#2019)
0a6d829cdd feat(tests): add test target generation to rust_canbench rule (#1347)
fcbc91f0a5 chore: update `ic-cdk` to 0.16.0 (#1868)
d1db89ed78 feat(ICRC-ledger): FI-1435: Implement V2 for ICRC ledger - use memory manager during upgrade (#1414)
6dcfafb491 feat(ICP-Ledger): FI-1433: Implement V1 for ICP ledger - add ability to read from memory manager in post_upgrade (#1020)
b886416ae6 fix(Ledger-Suite): changed IC version (#1839)
6dae2daa18 test(ICP_ledger): FI-1491: Add tests for existing ledger behavior regarding the anonymous principal (#1550)
3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
2a872112dd chore(ledgers): update mainnet-canisters.bzl (#1764)
abd1aa2753 test(ICRC_ledger): FI-1397: Add transaction generation to ICRC golden state tests (#1478)
```

#### Index

```
git log --format="%C(auto) %h %s" d4ee25b0865e89d3eaac13a60f0016d5e3296b31..e54d3fa34ded227c885d04e64505fa4b5d564743 -- rs/rosetta-api/icrc1/index-ng rs/ledger_suite/icrc1/index-ng
fcbc91f0a5 chore: update `ic-cdk` to 0.16.0 (#1868)
4eca90d6ec chore(Rosetta): FI-1512 move rosetta dependencies (#1801)
3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
83214c5c52 chore(ICRC-Index-ng): fix candid comment for get_account_transactions (#1681)
```

#### Archive

```
git log --format="%C(auto) %h %s" d4ee25b0865e89d3eaac13a60f0016d5e3296b31..e54d3fa34ded227c885d04e64505fa4b5d564743 -- rs/rosetta-api/icrc1/archive rs/ledger_suite/icrc1/archive
fcbc91f0a5 chore: update `ic-cdk` to 0.16.0 (#1868)
4eca90d6ec chore(Rosetta): FI-1512 move rosetta dependencies (#1801)
3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
```


## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
