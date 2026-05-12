# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e446c64d99a97e38166be23ff2bfade997d15ff7`

New compressed Wasm hash: `cf3bf8f87dc908be156f314fae3b83aae56d1f63e74a63c32994c4e02babdb2d`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/138740

---

## Motivation
Upgrade the ckBTC index canister to the latest version [ledger-suite-icrc-2025-10-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-10-27).


## Release Notes

```
git log --format='%C(auto) %h %s' 3f3d9bfac750f82f424185ac5b32a756cfd45ad9..e446c64d99a97e38166be23ff2bfade997d15ff7 -- rs/ledger_suite/icrc1/index-ng
7644b35479 feat(Ledgers): FI-1881: Check ledger liquid cycles balance before spawning archive (#7363)
aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
89d0cecc05 feat(ICRC_Index): FI-1849: Add support for fees in mint and burn blocks (#6508)
a50d51698f chore(Ledgers): Remove unused dependencies (#7012)
2f56f172a1 chore: bump rust to 1.89 (#6758)
1a7ae4c615 refactor(Ledgers): FI-1529: Extract ledger suite StateMachine helpers into a separate crate (#6812)
7baf5eedf4 chore: bumping edition to follow workspace edition in leftover Cargo.toml (#6779)
91f28f7e11 refactor(Ledger_suite): FI-1814: Move test_http_request_decoding_quota (#6729)
b9221277cd chore: bumping edition to 2024 (#6715)
 ```

## Upgrade args

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
