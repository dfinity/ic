# Proposal to upgrade the ckDOGE index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `653c927f2c732398bfd6e6b9dbfaf983cfb9b911`

New compressed Wasm hash: `815337e8b9a109954fa217e302c2c2022c5bf1b9a7d67b4f8e66f915500ffe46`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `ecnej-3aaaa-aaaar-qb3wq-cai`

Previous ckDOGE index proposal: https://dashboard.internetcomputer.org/proposal/140181

---

## Motivation
Upgrade the ckDOGE index canister to the latest version [ledger-suite-icrc-2026-02-02](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-02-02).


## Release Notes

```
git log --format='%C(auto) %h %s' e446c64d99a97e38166be23ff2bfade997d15ff7..653c927f2c732398bfd6e6b9dbfaf983cfb9b911 -- rs/ledger_suite/icrc1/index-ng
31f16206e2 feat(icrc-ledger-types): DEFI-1901: add ICRC-107 schema (#8068)
99e1260c41 chore(ICRC-Ledger): DEFI-2590: change fee collector tx field name from op to mthd (#8230)
01d37ee26d feat(ICRC_Ledger): DEFI-2541: Make tx.op string optional, but still require Operation in Transaction (#7848)
6f29cca118 test(ICRC_Index): DEFI-2541: Update expected error message in ICRC index tests (#8043)
b7b3ef2675 test(ICRC_Index): DEFI-2541: Add tests for unsupported blocks (#7952)
e5e0d13c08 test(ICRC_Index): DEFI-2527: index-ng u256 token testing (#7788)
b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
5db5614e28 feat(ICRC_Index): DEFI-1052: Only add block to account_block_ids once for self-transfer (#7744)
d66250e771 feat(ICRC-Index): add and handle ICRC-107 fee collector blocks (#7411)
 ```

## Upgrade args

```
git fetch
git checkout 653c927f2c732398bfd6e6b9dbfaf983cfb9b911
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 653c927f2c732398bfd6e6b9dbfaf983cfb9b911
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
```
