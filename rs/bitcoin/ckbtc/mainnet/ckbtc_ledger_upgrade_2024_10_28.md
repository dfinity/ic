# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e54d3fa34ded227c885d04e64505fa4b5d564743`

New compressed Wasm hash: `3d808fa63a3d8ebd4510c0400aa078e99a31afaa0515f0b68778f929ce4b2a46`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/133137

---

## Motivation
Upgrade the ckBTC ledger canister to the latest version to continue the migration towards stable memory.


## Upgrade args

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
cd rs/ledger_suite/icrc1/ledger
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes
The code for the ledger, index and archive canisters was moved from `rs/rosetta-api/icrc1` to `rs/ledger_suite/icrc1` as part of `3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)`. For this reason, the release notes below include the git log output for both directories.

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
## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
