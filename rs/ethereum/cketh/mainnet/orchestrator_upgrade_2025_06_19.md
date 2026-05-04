# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `83923a194d39835e8a7d9549f9f0831b962a60c2`

New compressed Wasm hash: `1e6837e141231499d0552290bd1165fd3a6cb0d3b68e72630a5da8a9c19314b8`

Upgrade args hash: `2524688457e7dc0ec7baff97fd8d44832bf4e905a0146703d66bab0651d2f5d1`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/136725

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest
version ([ledger-suite-icrc-2025-06-19](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-06-19)).

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26..83923a194d39835e8a7d9549f9f0831b962a60c2 -- rs/ethereum/ledger-suite-orchestrator
 02571e8215 feat(ICRC_Ledger): FI-1592: Implement ICRC-106 in the ICRC ledger (#2857)
```

### Ledger Suite

The commit used `83923a194d39835e8a7d9549f9f0831b962a60c2` corresponds to
the [ICRC Ledger Suite release 2025-06-19](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-06-19).

#### Ledger

```
git log --format="%C(auto) %h %s" fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26..83923a194d39835e8a7d9549f9f0831b962a60c2 -- rs/ledger_suite/icrc1/ledger
 83923a194d feat(ICRC_Ledger): FI-1771: Add 1xfer to icrc3_supported_block_types (#5608)
 00713b9827 feat(ICRC_Ledger): FI-1604: Set index in existing SNS and ck ledgers (#5237)
 3671acb49d chore: upgrade rust: 1.85.1 -> 1.86.0 (again) (#5453)
 995f15aed0 feat(Ledgers): FI-1666: Set upper limit for num_blocks_to_archive (#5215)
 e94aa05386 test(Ledgers): FI-1652: Add instruction limit test for ledger archiving (#4961)
 02571e8215 feat(ICRC_Ledger): FI-1592: Implement ICRC-106 in the ICRC ledger (#2857)
 029ebf5c44 chore: Upgrade canbench to 0.15.0 (#5356)
 2cc5b2479b chore(ICRC_Ledger): FI-1726: Use test_strategy instead of proptest macro for ICRC1 ledger suite tests (#5039)
```

#### Index

```
git log --format="%C(auto) %h %s" fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26..83923a194d39835e8a7d9549f9f0831b962a60c2 -- rs/ledger_suite/icrc1/index-ng
 02571e8215 feat(ICRC_Ledger): FI-1592: Implement ICRC-106 in the ICRC ledger (#2857)
```

#### Archive

```
git log --format="%C(auto) %h %s" fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26..83923a194d39835e8a7d9549f9f0831b962a60c2 -- rs/ledger_suite/icrc1/archive
 83923a194d feat(ICRC_Ledger): FI-1771: Add 1xfer to icrc3_supported_block_types (#5608)
```

## Upgrade args

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "83923a194d39835e8a7d9549f9f0831b962a60c2"; ledger_compressed_wasm_hash = opt "40fa0b06370e6a80a8f2290eb55ab98aba5e1c8e25130f50da8ac0908f8a3511"; index_compressed_wasm_hash = opt "6c406b9dc332f3dc58b823518ab2b2c481467307ad9e540122f17bd9b926c123"; archive_compressed_wasm_hash = opt "4ba40fe3a065da17b5a169ea3f4232bbb27539dc06ea0514b9baf06a86d8f7a4"}})' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hashes of the gzipped WASMs for the ledger, index and archive match the proposed hashes in the upgrade
arguments.

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```