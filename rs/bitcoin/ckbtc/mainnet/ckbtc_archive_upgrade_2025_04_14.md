# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `512cf412f33d430b79f42330518166d14fc6884e`

New compressed Wasm hash: `649401fd06e58e61aea55747961d5144af673b5e70bccd005898a6da65c84c29`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/135858

---

## Motivation

Upgrade ckBTC archive canister to the latest
version [ledger-suite-icrc-2025-04-14](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-04-14).

## Release Notes

No changes since last version (0d96610b842ca721e50169c65bdfbc5d6d3d8b67).

```
git log --format='%C(auto) %h %s' 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ledger_suite/icrc1/archive
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
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
