# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `3f3d9bfac750f82f424185ac5b32a756cfd45ad9`

New compressed Wasm hash: `73eb5d98d6e7020cd99a3430ef1284c05e2a708ae5274ca0387deca7551265e5`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/137359

---

## Motivation

Upgrade the ckBTC index canister to the latest
version [ledger-suite-icrc-2025-09-01](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-09-01).


## Release Notes

```
git log --format='%C(auto) %h %s' 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ledger_suite/icrc1/index-ng
49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
2ee6ac954b chore(Ledgers): format did files with default formatter (#6235)
0fbd33e753 test(Ledgers): FI-1459: Add transfer_from to valid_transactions_strategy (#5592)
 ```

## Upgrade args

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
