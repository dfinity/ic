# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c741e349451edf0c9792149ad439bb32a0161371`

New compressed Wasm hash: `3b03d1bb1145edbcd11101ab2788517bc0f427c3bd7b342b9e3e7f42e29d5822`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/134450

---

## Motivation

Upgrade the ckBTC ledger canister to the latest version ([ledger-suite-icrc-2025-01-07](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-01-07)) to continue the migration towards stable memory.

## Upgrade args

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
cd rs/ledger_suite/icrc1/ledger
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ledger_suite/icrc1/ledger
c741e34945 feat: ICRC-ledger: FI-1439: Implement V4 for ICRC ledger - migrate balances to stable structures (#2901)
ddadaafd51 test(ICP_Ledger): FI-1616: Fix ICP ledger upgrade tests (#3213)
dfc3810851 fix(ICRC-Ledger): changed certificate version (#2848)
b006ae9934 feat(ICP-ledger): FI-1438: Implement V3 for ICP ledger - migrate allowances to stable structures (#2818)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
