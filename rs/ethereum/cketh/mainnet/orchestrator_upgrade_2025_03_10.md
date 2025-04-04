# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `0d96610b842ca721e50169c65bdfbc5d6d3d8b67`

New compressed Wasm hash: `6636c8fd14425cf1a2674fc0539adb8ab49b0737b6d48e486da8266eb4437b11`

Upgrade args hash: `f4f5d2dafb322e7c543d7533cf7086ec9b46bd556b416b1fb89e883aa0826ab1`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/134785

---

## Motivation
Upgrade all ledger suites managed by the orchestrator to the latest
version ([ledger-suite-icrc-2025-02-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27)) to
continue the migration towards stable memory.


## Upgrade args

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "0d96610b842ca721e50169c65bdfbc5d6d3d8b67"; ledger_compressed_wasm_hash = opt "d94d8283e2a71550bac5da0365ca719545e97d05c88787efb679993e2e8c12f4"; index_compressed_wasm_hash = opt "2e971761ca87928807d736c152afbfcbabb8a7b1dbdf46539702f8671286d577"; archive_compressed_wasm_hash = opt "1057c058587858729cb183f008c06210920bd34dfab85e62388e71a8033d0302"}})' | xxd -r -p | sha256sum
```

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ethereum/ledger-suite-orchestrator
810eeb14ca chore: use cdk::api::in_replicated_execution (#3949)
6612119c34 chore: Bump ic_cdk version (#3939)
5506c7c41e chore: [EXC-1835] Make ic-management-canister-types private (#3814)
841793d547 chore: add MetricsAssert test utility (#3375)
 ```

### Ledger Suite

The commit used `0d96610b842ca721e50169c65bdfbc5d6d3d8b67` corresponds to
the [ICRC Ledger Suite releast 2025-02-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-02-27).

#### Ledger

```
git log --format="%C(auto) %h %s" c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ledger_suite/icrc1/ledger
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

#### Index

```
git log --format="%C(auto) %h %s" c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ledger_suite/icrc1/index-ng
88c50f7bb2 feat(ICRC_Ledger): FI-1558: Set 10Tcycles default value for cycles for archive creation (#3653)
cc12560396 test(ICRC_Index): FI-1042: Verify ICRC ledger and index block equality (#3403)
```

#### Archive

```
git log --format="%C(auto) %h %s" c741e349451edf0c9792149ad439bb32a0161371..0d96610b842ca721e50169c65bdfbc5d6d3d8b67 -- rs/ledger_suite/icrc1/archive
6b7b92b24a test(ICRC_Ledger): FI-1043: Verify ICRC ledger and archive block equality (#3404)
```


## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout 0d96610b842ca721e50169c65bdfbc5d6d3d8b67
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
