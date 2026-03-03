# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `653c927f2c732398bfd6e6b9dbfaf983cfb9b911`

New compressed Wasm hash: `cd78959e48c84925da9c1e207301d4fecce6aedd676801e1edbe763c50031f93`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/139990

---

## Motivation
Upgrade the ckBTC archive canister to the latest version [ledger-suite-icrc-2026-02-02](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-02-02).


## Release Notes

```
git log --format='%C(auto) %h %s' e446c64d99a97e38166be23ff2bfade997d15ff7..653c927f2c732398bfd6e6b9dbfaf983cfb9b911 -- rs/ledger_suite/icrc1/archive
31f16206e2 feat(icrc-ledger-types): DEFI-1901: add ICRC-107 schema (#8068)
cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
99e1260c41 chore(ICRC-Ledger): DEFI-2590: change fee collector tx field name from op to mthd (#8230)
3034c5c54b fix: revert "chore: rust 1.90.0 -> 1.91.1 (#8023)" (#8197)
6f73a21b56 chore: rust 1.90.0 -> 1.91.1 (#8023)
01d37ee26d feat(ICRC_Ledger): DEFI-2541: Make tx.op string optional, but still require Operation in Transaction (#7848)
aeae9f675b feat(ICRC-Archive): DEFI-1906: add 107feecol to the list of supported block types (#7795)
d66250e771 feat(ICRC-Index): add and handle ICRC-107 fee collector blocks (#7411)
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
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
