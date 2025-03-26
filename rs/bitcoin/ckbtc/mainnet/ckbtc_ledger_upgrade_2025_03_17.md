# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `0d96610b842ca721e50169c65bdfbc5d6d3d8b67`

New compressed Wasm hash: `dca85fc694c18181b5c67c93194a7fc72f00226f3b54ac6e4630a9dfe8187503`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/134898

---

## Motivation
Upgrade the ckBTC ledger canister to the latest version ([ledger-suite-icrc-2025-02-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27)) to finish the migration towards stable memory.

## Upgrade args

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
cd rs/ledger_suite/icrc1/ledger
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ledger_suite/icrc1/ledger
0d96610b84 feat(ICRC-Ledger): FI-1441: migrate ledger blocks to stable structures (#3695)
a4b98fca74 chore(ICP-Ledger): remove dfn_core from icp ledger lib (#4095)
88c50f7bb2 feat(ICRC_Ledger): FI-1558: Set 10Tcycles default value for cycles for archive creation (#3653)
c116fae44c feat(ICRC_Ledger): FI-1664: Forbid setting interpreted ICRC ledger metadata (#3767)
215a697e14 feat: ICP-ledger: FI-1440: Implement V4 for ICP ledger - migrate balances to stable structures (#3314)
73f1dbd198 chore: add V3 to ICRC Ledger canister revisions and update mainnet to V4 (#3570)
7f0bad6c91 chore: add todo comment to remind of disabling balances serialization (#3579)
be8de19811 fix(ICRC_Ledger): FI-1645: use default deserialization value of 0 for ledger state's ledger_version (#3520)
fc2787097c chore: bump rust to 1.84 (#3469)
d6bb598cfc test(ICRC_Ledger): canbench benchmarks for icrc2_approve, icrc2_transfer_from and icrc3_get_blocks (#3400)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
