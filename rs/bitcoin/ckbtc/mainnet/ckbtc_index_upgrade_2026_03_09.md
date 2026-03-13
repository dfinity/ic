# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `cf41372e3d4dc1accfe2c09a7969f8bddc729dc1`

New compressed Wasm hash: `dab6808d0dfc06e5e88336d0c3d3e45e5448c6e36c2a781f3e9e09bd450f528c`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/140519

---

## Motivation
Upgrade the ckBTC index canister to the latest version [ledger-suite-icrc-2026-03-09](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-03-09).


## Release Notes

```
git log --format='%C(auto) %h %s' 653c927f2c732398bfd6e6b9dbfaf983cfb9b911..cf41372e3d4dc1accfe2c09a7969f8bddc729dc1 -- rs/ledger_suite/icrc1/index-ng
c199eff5ab feat(ICRC_Index): DEFI-2684: Variable build_index wait time (#9060)
 ```

## Upgrade args

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
