# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26`

New compressed Wasm hash: `91f5c6d260d0ff796e74e67c9f1b43f5fc6f2dadb8ad6ea0d77cbd6e5fff807b`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/136424

---

## Motivation

Upgrade ckBTC ledger canister to the latest
version [ledger-suite-icrc-2025-05-22](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-05-22).

## Release Notes

```
git log --format='%C(auto) %h %s' 512cf412f33d430b79f42330518166d14fc6884e..fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26 -- rs/ledger_suite/icrc1/ledger
1f71efe574 feat(ICRC-Ledger): FI-1546: Implement the ICRC-103 standard (#4840)
33e44adbae chore(Ledgers): FI-1731: Update ledger suite mainnet canisters json (#5146)
92051ebe9d test(ICRC_Ledger): FI-1732: Re-enable test_icrc1_test_suite test (#5151)
b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
f68a58fab6 chore: update Rust to 1.85.1 (#4340)
3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
b0cbc5c187 feat(ICRC_Ledger): FI-1660: Forbid setting fee collector to minting account (#3800)
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
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```