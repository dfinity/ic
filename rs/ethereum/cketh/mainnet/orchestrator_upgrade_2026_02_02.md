# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `653c927f2c732398bfd6e6b9dbfaf983cfb9b911`

New compressed Wasm hash: `649d3cd0418d93113b430a0040e87637d410fd3072e6a2238c025a75bd3b1f20`

Upgrade args hash: `6d6fdedf120e1c7df976745bb676e1d076f1afa8ab6209037e92e41b6fa60158`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/139936

---

## Motivation
Upgrade all ledger suites managed by the orchestrator to the latest version ([ledger-suite-icrc-2026-02-02](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-02-02)).


## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' e446c64d99a97e38166be23ff2bfade997d15ff7..653c927f2c732398bfd6e6b9dbfaf983cfb9b911 -- rs/ethereum/ledger-suite-orchestrator
da3f9151f9 feat(icrc-ledger-types): add MetadataKey type (#8216)
ceb4b666c4 chore: Bump askama version and remove build.rs workaround (#8407)
cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
3034c5c54b fix: revert "chore: rust 1.90.0 -> 1.91.1 (#8023)" (#8197)
6f73a21b56 chore: rust 1.90.0 -> 1.91.1 (#8023)
b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
 ```

### Ledger Suite

The commit used
`653c927f2c732398bfd6e6b9dbfaf983cfb9b911` corresponds to the [ICRC Ledger Suite release 2026-02-02](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-02-02).

#### Ledger

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2025-10-27..ledger-suite-icrc-2026-02-02 -- rs/ledger_suite/common rs/ledger_suite/icrc1/ledger rs/ledger_suite/icrc1/src rs/ledger_suite/icrc1/tokens_u256 packages/icrc-ledger-types
 1322054537 chore(ICRC-Ledger): DEFI-2625: remove stable structures migration code (#8492)
 ccad686b37 chore: Drop unused dependencies (#8470)
 da3f9151f9 feat(icrc-ledger-types): add MetadataKey type (#8216)
 84bb5294a4 chore: revert rust 1.92.0 -> 1.90.0 (#8278)
 31f16206e2 feat(icrc-ledger-types): DEFI-1901: add ICRC-107 schema (#8068)
 cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
 99e1260c41 chore(ICRC-Ledger): DEFI-2590: change fee collector tx field name from op to mthd (#8230)
 3034c5c54b fix: revert "chore: rust 1.90.0 -> 1.91.1 (#8023)" (#8197)
 6f73a21b56 chore: rust 1.90.0 -> 1.91.1 (#8023)
 01d37ee26d feat(ICRC_Ledger): DEFI-2541: Make tx.op string optional, but still require Operation in Transaction (#7848)
 c0cdf468fb feat(ICRC_Ledger): DEFI-2541: Manual Block deserializer implementation (#7847)
 b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
 160251a91f chore(ICRC_Ledger): Clean up unused serialization (#7819)
 a406dd5d9c chore(Ledgers): DEFI-2520: Change ARCHIVING_FAILURES to Cell (#7752)
 d66250e771 feat(ICRC-Index): add and handle ICRC-107 fee collector blocks (#7411)
 dede7e4fb6 chore: bump candid to v0.10.20 (#7704)
 cf23b5772a chore(ICRC_Ledger): Remove unused TryFrom impl (#7459)
 2f23be1998 fix(icrc-ledger-types): remove unnecessary fee from the schema (#7475)
 0fa6ab41c1 feat: use single bazel repository for mainnet canisters (#7421)
```

#### Index

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2025-10-27..ledger-suite-icrc-2026-02-02 -- rs/ledger_suite/icrc1/index-ng
 31f16206e2 feat(icrc-ledger-types): DEFI-1901: add ICRC-107 schema (#8068)
 99e1260c41 chore(ICRC-Ledger): DEFI-2590: change fee collector tx field name from op to mthd (#8230)
 01d37ee26d feat(ICRC_Ledger): DEFI-2541: Make tx.op string optional, but still require Operation in Transaction (#7848)
 6f29cca118 test(ICRC_Index): DEFI-2541: Update expected error message in ICRC index tests (#8043)
 b7b3ef2675 test(ICRC_Index): DEFI-2541: Add tests for unsupported blocks (#7952)
 e5e0d13c08 test(ICRC_Index): DEFI-2527: index-ng u256 token testing (#7788)
 b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
 5db5614e28 feat(ICRC_Index): DEFI-1052: Only add block to account_block_ids once for self-transfer (#7744)
 d66250e771 feat(ICRC-Index): add and handle ICRC-107 fee collector blocks (#7411)
```

#### Archive

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2025-10-27..ledger-suite-icrc-2026-02-02 -- rs/ledger_suite/icrc1/archive/
 31f16206e2 feat(icrc-ledger-types): DEFI-1901: add ICRC-107 schema (#8068)
 cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
 99e1260c41 chore(ICRC-Ledger): DEFI-2590: change fee collector tx field name from op to mthd (#8230)
 3034c5c54b fix: revert "chore: rust 1.90.0 -> 1.91.1 (#8023)" (#8197)
 6f73a21b56 chore: rust 1.90.0 -> 1.91.1 (#8023)
 01d37ee26d feat(ICRC_Ledger): DEFI-2541: Make tx.op string optional, but still require Operation in Transaction (#7848)
 aeae9f675b feat(ICRC-Archive): DEFI-1906: add 107feecol to the list of supported block types (#7795)
 d66250e771 feat(ICRC-Index): add and handle ICRC-107 fee collector blocks (#7411)
 0fa6ab41c1 feat: use single bazel repository for mainnet canisters (#7421)
```

## Upgrade args

```
git fetch
git checkout 653c927f2c732398bfd6e6b9dbfaf983cfb9b911
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(
  variant {
    UpgradeArg = record {
      git_commit_hash = opt "653c927f2c732398bfd6e6b9dbfaf983cfb9b911";
      ledger_compressed_wasm_hash = opt "3eee89dc60cf1d7fa16c3109c5b492d740042ec71918ed699ae12b43cac77a81";
      index_compressed_wasm_hash = opt "815337e8b9a109954fa217e302c2c2022c5bf1b9a7d67b4f8e66f915500ffe46";
      archive_compressed_wasm_hash = opt "08e12f7c3ec321bc42bdf0413f30f615124ae44ebbc4705a3138bfffef21f382";
    }
  },
)' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 653c927f2c732398bfd6e6b9dbfaf983cfb9b911
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hashes of the gzipped WASMs for the ledger, index and archive match the proposed hashes in the upgrade arguments.

```
git fetch
git checkout 653c927f2c732398bfd6e6b9dbfaf983cfb9b911
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
