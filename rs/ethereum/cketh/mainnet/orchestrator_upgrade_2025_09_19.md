# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `3f3d9bfac750f82f424185ac5b32a756cfd45ad9`

New compressed Wasm hash: `65922cb648428a74535c5aa58a36adacb508f6aa0609298030395d39b84e8453`

Upgrade args hash: `bb60ab96aacd95356d66cbb608ec81622efc29a65d84ad7e32b3e3fa603c8f99`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/137335

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest
version ([ledger-suite-icrc-2025-09-01](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-09-01)).

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ethereum/ledger-suite-orchestrator
 49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
 55ec0283bb build: update ic0 to v1.0.0. (#6216)
 a4c1c9bce1 chore: update rust to 1.88.0 (#6045)
```

### Ledger Suite

The commit used `3f3d9bfac750f82f424185ac5b32a756cfd45ad9` corresponds to
the [ICRC Ledger Suite release 2025-09-19](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-09-19).

#### Ledger

```
git log --format="%C(auto) %h %s" 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ledger_suite/icrc1/ledger
 e3857ed56a feat(ICRC-Ledger): FI-1653: Ensure upgrade u64 <-> u256 fails (#6486)
 19a45d5b7f test(ICRC_Ledger): FI-1834: Add check for number of blocks returned in test_icrc3_get_blocks (#6399)
 f322cac905 fix(Ledgers): verify fee when generating ICRC-21 consent message (#6381)
 49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
 cddf2f8a99 chore(ICRC_Ledger): FI-1747: Clean up ICRC-106 migration code (#5627)
 2ee6ac954b chore(Ledgers): format did files with default formatter (#6235)
 3889808133 feat(ledgers): FI-1659: fix the generic ICRC-21 message, add FieldsDisplay (#5563)
 6045144d84 chore(Ledgers): FI-1252: Remove unused dependencies (#6193)
 a4c1c9bce1 chore: update rust to 1.88.0 (#6045)
 d890a928d9 test(ICRC_Ledger): FI-1793: Fix allowance checking flakiness in golden state tests (#5914)
 e73c4081d3 test(ICRC_Ledger): FI-1592: Add test with unsupported ledger init args (#5452)
 6e91324ffc chore(IDX): bump timeout for ledger_test (#5682)
```

#### Index

```
git log --format="%C(auto) %h %s" 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ledger_suite/icrc1/index-ng
 49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
 2ee6ac954b chore(Ledgers): format did files with default formatter (#6235)
 0fbd33e753 test(Ledgers): FI-1459: Add transfer_from to valid_transactions_strategy (#5592)
```

#### Archive

```
git log --format="%C(auto) %h %s" 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ledger_suite/icrc1/archive
 49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
 2ee6ac954b chore(Ledgers): format did files with default formatter (#6235)
```

## Upgrade args

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "3f3d9bfac750f82f424185ac5b32a756cfd45ad9"; ledger_compressed_wasm_hash = opt "d602c900543073178bddea5bda3f89dd5cfc3dfecda88ed241424955656e7043"; index_compressed_wasm_hash = opt "b39d419cdd290515cf4c16a6878c8bb1a25697ee4d4678c895475e3322ed7d64"; archive_compressed_wasm_hash = opt "80416919154866c86bd1eb5f480fda36ca7354bff29c1760847098bf01d22d03"}})' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hashes of the gzipped WASMs for the ledger, index and archive match the proposed hashes in the upgrade
arguments.

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
