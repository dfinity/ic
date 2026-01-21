# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e446c64d99a97e38166be23ff2bfade997d15ff7`

New compressed Wasm hash: `186697235c7072e94fa04e5c51a06af8500e8b36835420a9284912b977ae21a9`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/138742

---

## Motivation
Upgrade the ckBTC archive canister to the latest version [ledger-suite-icrc-2025-10-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-10-27).


## Release Notes

```
git log --format='%C(auto) %h %s' 3f3d9bfac750f82f424185ac5b32a756cfd45ad9..e446c64d99a97e38166be23ff2bfade997d15ff7 -- rs/ledger_suite/icrc1/archive
aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
a50d51698f chore(Ledgers): Remove unused dependencies (#7012)
2f56f172a1 chore: bump rust to 1.89 (#6758)
91f28f7e11 refactor(Ledger_suite): FI-1814: Move test_http_request_decoding_quota (#6729)
b9221277cd chore: bumping edition to 2024 (#6715)
28de7a00e3 feat(ICRC-Archive): FI-1844: Ensure upgrade u64 <-> u256 fails (#6546)
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
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
