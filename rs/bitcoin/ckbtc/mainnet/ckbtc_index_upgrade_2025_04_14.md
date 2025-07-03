# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `512cf412f33d430b79f42330518166d14fc6884e`

New compressed Wasm hash: `a63b9628d45858b02eba1185c525c527c673746f4b57f6238822fd9f99907ae5`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/135856

---

## Motivation

Upgrade ckBTC index canister to the latest
version [ledger-suite-icrc-2025-04-14](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-04-14).

## Release Notes

```
git log --format='%C(auto) %h %s' 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ledger_suite/icrc1/index-ng
4d40e10c75 chore(IDX): use correct .gz name for canisters (#4300)
 ```

## Upgrade args

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```