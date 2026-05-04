# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `83923a194d39835e8a7d9549f9f0831b962a60c2`

New compressed Wasm hash: `b2795770be28a8962c953a8b44ff26ea5a61995828ba15c3812793c8670801f4`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/136724

---

## Motivation

Upgrade ckBTC index canister to the latest
version [ledger-suite-icrc-2025-06-19](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-06-19).

## Release Notes

```
git log --format='%C(auto) %h %s' fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26..83923a194d39835e8a7d9549f9f0831b962a60c2 -- rs/ledger_suite/icrc1/index-ng
02571e8215 feat(ICRC_Ledger): FI-1592: Implement ICRC-106 in the ICRC ledger (#2857)
 ```

## Upgrade args

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```