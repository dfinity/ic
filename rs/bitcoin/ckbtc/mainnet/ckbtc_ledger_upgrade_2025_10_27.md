# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e446c64d99a97e38166be23ff2bfade997d15ff7`

New compressed Wasm hash: `71c27c5dc10034a1175296892b37827df0265d0ae072f5c59e99b8a1f6c45c76`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/138741

---

## Motivation
Upgrade the ckBTC ledger canister to the latest version [ledger-suite-icrc-2025-10-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-10-27).


## Release Notes

```
git log --format='%C(auto) %h %s' 3f3d9bfac750f82f424185ac5b32a756cfd45ad9..e446c64d99a97e38166be23ff2bfade997d15ff7 -- rs/ledger_suite/icrc1/ledger
7644b35479 feat(Ledgers): FI-1881: Check ledger liquid cycles balance before spawning archive (#7363)
b358d80102 chore: upgrade rust: 1.89.0 -> 1.90.0 (#7322)
aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
d3f6d031b7 test(Ledgers): FI-1881: Add tests for archive spawning with cycles attached (#7221)
2f56f172a1 chore: bump rust to 1.89 (#6758)
3fccd4e885 refactor(Ledgers): FI-1530: Extract InMemoryLedger into separate crate (#6847)
1a7ae4c615 refactor(Ledgers): FI-1529: Extract ledger suite StateMachine helpers into a separate crate (#6812)
143ab585d5 refactor(Ledgers): FI-1814: Extract some consts into ic-ledger-suite-state-machine-tests-constants crate (#6733)
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
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
