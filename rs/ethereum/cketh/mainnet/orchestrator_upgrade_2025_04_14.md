# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `512cf412f33d430b79f42330518166d14fc6884e`

New compressed Wasm hash: `3ed42a26b7557ca40bc769fe25901579a773208167b2efe4525a72d43e680700`

Upgrade args hash: `5e7ecdf15161ecc5fbfee84d6f0f77af13fc604a7eac0726450c3cc14d3b67bc`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/135748

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest
version ([ledger-suite-icrc-2025-04-14](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-04-14)).

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ethereum/ledger-suite-orchestrator
0aee1dee5e chore(IDX): load ledger suite orchestrator wasm directly (#4322)
 ```

### Ledger Suite

The commit used `512cf412f33d430b79f42330518166d14fc6884e` corresponds to
the [ICRC Ledger Suite release 2025-04-14](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-04-14).

#### Ledger

```
git log --format="%C(auto) %h %s" 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ledger_suite/icrc1/ledger
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

#### Index

```
git log --format="%C(auto) %h %s" 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ledger_suite/icrc1/index-ng
 4d40e10c75 chore(IDX): use correct .gz name for canisters (#4300)
```

#### Archive

No changes since last version (`0d96610b842ca721e50169c65bdfbc5d6d3d8b67`).


```
git log --format="%C(auto) %h %s" 0d96610b842ca721e50169c65bdfbc5d6d3d8b67..512cf412f33d430b79f42330518166d14fc6884e -- rs/ledger_suite/icrc1/archive
```

## Upgrade args

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "512cf412f33d430b79f42330518166d14fc6884e"; ledger_compressed_wasm_hash = opt "b5a17d640743711184ac16e49608a6590c750d32cda70817b7d43a3a67e7cfdf"; index_compressed_wasm_hash = opt "02dc57b933ea8259e86ce51d10c067cf5939008ecf62e35a25276ff9fa1510b9"; archive_compressed_wasm_hash = opt "3fafdd895c44886e38199882afcf06efb8e6e0b73af51eca327dcba4da7a0106"}})' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout 512cf412f33d430b79f42330518166d14fc6884e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
