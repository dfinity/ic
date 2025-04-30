# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c741e349451edf0c9792149ad439bb32a0161371`

New compressed Wasm hash: `e155db9d06b6147ece4f9defe599844f132a7db21693265671aa6ac60912935f`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/134449

---

## Motivation

Upgrade the ckBTC index canister to the same version ([ledger-suite-icrc-2025-01-07](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-01-07)) as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.

## Upgrade args

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
cd rs/ledger_suite/icrc1/index-ng
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ledger_suite/icrc1/index-ng
c741e34945 feat: ICRC-ledger: FI-1439: Implement V4 for ICRC ledger - migrate balances to stable structures (#2901)
575ca531a7 chore(ICRC_Index): FI-1468: Remove old ICRC index canister (#3286)
8d4fcddc6e test(ICRC_Index): FI-1617: Optimize retrieve_blocks_from_ledger_interval tests (#3236)
e369646b76 fix: Use default rust edition instead of specifying it in the BUILD rules (#3047)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
