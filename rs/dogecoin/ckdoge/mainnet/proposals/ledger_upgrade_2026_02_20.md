# Proposal to upgrade the ckDOGE ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `653c927f2c732398bfd6e6b9dbfaf983cfb9b911`

New compressed Wasm hash: `3eee89dc60cf1d7fa16c3109c5b492d740042ec71918ed699ae12b43cac77a81`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `efmc5-wyaaa-aaaar-qb3wa-cai`

Previous ckDOGE ledger proposal: https://dashboard.internetcomputer.org/proposal/140182

---

## Motivation
Upgrade the ckDOGE ledger canister to the latest version [ledger-suite-icrc-2026-02-02](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-02-02).


## Release Notes

```
git log --format='%C(auto) %h %s' e446c64d99a97e38166be23ff2bfade997d15ff7..653c927f2c732398bfd6e6b9dbfaf983cfb9b911 -- rs/ledger_suite/icrc1/ledger
1322054537 chore(ICRC-Ledger): DEFI-2625: remove stable structures migration code (#8492)
da3f9151f9 feat(icrc-ledger-types): add MetadataKey type (#8216)
84bb5294a4 chore: revert rust 1.92.0 -> 1.90.0 (#8278)
31f16206e2 feat(icrc-ledger-types): DEFI-1901: add ICRC-107 schema (#8068)
cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
99e1260c41 chore(ICRC-Ledger): DEFI-2590: change fee collector tx field name from op to mthd (#8230)
3034c5c54b fix: revert "chore: rust 1.90.0 -> 1.91.1 (#8023)" (#8197)
6f73a21b56 chore: rust 1.90.0 -> 1.91.1 (#8023)
01d37ee26d feat(ICRC_Ledger): DEFI-2541: Make tx.op string optional, but still require Operation in Transaction (#7848)
b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
a406dd5d9c chore(Ledgers): DEFI-2520: Change ARCHIVING_FAILURES to Cell (#7752)
d66250e771 feat(ICRC-Index): add and handle ICRC-107 fee collector blocks (#7411)
dede7e4fb6 chore: bump candid to v0.10.20 (#7704)
0fa6ab41c1 feat: use single bazel repository for mainnet canisters (#7421)
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
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
```
