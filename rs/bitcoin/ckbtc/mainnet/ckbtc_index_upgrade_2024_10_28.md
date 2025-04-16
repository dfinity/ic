# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e54d3fa34ded227c885d04e64505fa4b5d564743`

New compressed Wasm hash: `67b5f0bf128e801adf4a959ea26c3c9ca0cd399940e169a26a2eb237899a94dd`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/133136

---

## Motivation
Upgrade the ckBTC index canister to the same version as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.


## Upgrade args

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
cd rs/ledger_suite/icrc1/index-ng
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes
The code for the ledger, index and archive canisters was moved from `rs/rosetta-api/icrc1` to `rs/ledger_suite/icrc1` as part of `3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)`. For this reason, the release notes below include the git log output for both directories.

```
git log --format="%C(auto) %h %s" d4ee25b0865e89d3eaac13a60f0016d5e3296b31..e54d3fa34ded227c885d04e64505fa4b5d564743 -- rs/rosetta-api/icrc1/index-ng rs/ledger_suite/icrc1/index-ng
fcbc91f0a5 chore: update `ic-cdk` to 0.16.0 (#1868)
4eca90d6ec chore(Rosetta): FI-1512 move rosetta dependencies (#1801)
3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
83214c5c52 chore(ICRC-Index-ng): fix candid comment for get_account_transactions (#1681)
```
## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e54d3fa34ded227c885d04e64505fa4b5d564743
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
