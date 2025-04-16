# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c741e349451edf0c9792149ad439bb32a0161371`

New compressed Wasm hash: `2b0970a84976bc2eb9591b68d44501566937994fa5594972f8aac9c8b058672f`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/134451

---

## Motivation

Upgrade the ckBTC archive canister to the same version ([ledger-suite-icrc-2025-01-07](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-01-07)) as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.

## Upgrade args

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
cd rs/ledger_suite/icrc1/archive
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

No changes since last version (`2190613d3b5bcd9b74c382b22d151580b8ac271a`).

```
git log --format='%C(auto) %h %s' 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ledger_suite/icrc1/archive
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
