# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `3f3d9bfac750f82f424185ac5b32a756cfd45ad9`

New compressed Wasm hash: `cb3f2ecc540f3b4c073f1a4de1fc4a9cef11cb1901405f49f9ef855a53b69e1c`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/137361

---

## Motivation

Upgrade the ckBTC archive canister to the latest
version [ledger-suite-icrc-2025-09-01](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-09-01).

## Release Notes

```
git log --format='%C(auto) %h %s' 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ledger_suite/icrc1/archive
49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
2ee6ac954b chore(Ledgers): format did files with default formatter (#6235)
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
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
