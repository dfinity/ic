# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `0d96610b842ca721e50169c65bdfbc5d6d3d8b67`

New compressed Wasm hash: `58c682f5a22b3ad59d9bfbef5570b638c44baf01d0c82e5889593491e841b64f`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/134897

---

## Motivation
Upgrade the ckBTC index canister to the same version ([ledger-suite-icrc-2025-02-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27)) as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.


## Upgrade args

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
cd rs/ledger_suite/icrc1/index-ng
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ledger_suite/icrc1/index-ng
88c50f7bb2 feat(ICRC_Ledger): FI-1558: Set 10Tcycles default value for cycles for archive creation (#3653)
cc12560396 test(ICRC_Index): FI-1042: Verify ICRC ledger and index block equality (#3403)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
