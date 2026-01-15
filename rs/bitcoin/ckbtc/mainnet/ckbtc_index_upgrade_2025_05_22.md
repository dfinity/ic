# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26`

New compressed Wasm hash: `2e98628c89f44c04a3b7d2da507163ef6360278bf62e1c0d0f98732c980565f7`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/136421

---

## Motivation

Upgrade ckBTC index canister to the latest
version [ledger-suite-icrc-2025-05-22](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-05-22).

## Release Notes

```
git log --format='%C(auto) %h %s' 512cf412f33d430b79f42330518166d14fc6884e..fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26 -- rs/ledger_suite/icrc1/index-ng
b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
ecb620b09d chore(ICRC_Index_NG): FI-1594: Change the type of fee and amount to Tokens (#3368)
c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
 ```

## Upgrade args

```
git fetch
git checkout fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```