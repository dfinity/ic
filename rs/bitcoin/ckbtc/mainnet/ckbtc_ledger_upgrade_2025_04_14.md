# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `512cf412f33d430b79f42330518166d14fc6884e`

New compressed Wasm hash: `901bc548f901145bd15a1156487eed703705794ad6a23787eaa04b1c7bbdcf48`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/135857

---

## Motivation

Upgrade ckBTC ledger canister to the latest
version [ledger-suite-icrc-2025-04-14](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-04-14).

## Release Notes

```
git log --format='%C(auto) %h %s' 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ledger_suite/icrc1/ledger
5599a98606 fix(ICRC_Ledger): FI-1709: Recompute ICRC ledger certified data in post upgrade (#4796)
8db45d0ad9 test(Ledger): FI-1689: Tests for archive chunking and ranges (#4678)
32082e416e feat(ICRC_Ledger): FI-1702: Always return ICRC-3 compliant certificate from ICRC ledger (#4504)
e669604b02 chore(ICP-Ledger): remove stable structures migration code (#4630)
6973bac7af feat(Ledger_Canister_Core): FI-1689: Report ledger blocks in at most one location (#4264)
c3f0331bc7 feat(ICRC_Ledger): FI-1657: Export total volume counter metric for ICRC ledger (#4166)
9feabf95ab chore(Ledgers): remove unused dfn build dependencies (#4465)
219abad147 feat(ICP-Ledger): FI-1442: migrate ledger blocks to stable structures  (#3836)
f6f5e0927d chore: upgrade stable-structures (#4284)
4d40e10c75 chore(IDX): use correct .gz name for canisters (#4300)
a05c88a234 test(ICRC_Ledger): FI-1652: Add tests for archiving large amounts of blocks (#4235)
f0ed1f2268 feat(ICRC_Ledger): FI-1675: Add ICRC-10 to list of supported standards of ICRC ledger (#4175)
 ```

## Upgrade args

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```