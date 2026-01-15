# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `0d96610b842ca721e50169c65bdfbc5d6d3d8b67`

New compressed Wasm hash: `9bb1d4c4012eb6009a901f6d18eb015ca41fbcaadf8cf0ffe7c774a0d7d59d4a`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/134899

---

## Motivation
Upgrade the ckBTC archive canister to the same version ([ledger-suite-icrc-2025-02-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27)) as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.


## Upgrade args

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
cd rs/ledger_suite/icrc1/archive
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ledger_suite/icrc1/archive
6b7b92b24a test(ICRC_Ledger): FI-1043: Verify ICRC ledger and archive block equality (#3404)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
