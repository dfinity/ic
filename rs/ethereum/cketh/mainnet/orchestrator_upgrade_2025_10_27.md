# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e446c64d99a97e38166be23ff2bfade997d15ff7`

New compressed Wasm hash: `1a668b49dc2ba055c88560cd797077aa1d0c2f2e908cf0398046fb6d023daf1b`

Upgrade args hash: `3b662095428928eb1f9c1a6ebfa4e3fd05c8b9fb16dee2272c51ebab859d18f8`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/138707

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest version ([ledger-suite-icrc-2025-10-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-10-27)).

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' 3f3d9bfac750f82f424185ac5b32a756cfd45ad9..e446c64d99a97e38166be23ff2bfade997d15ff7 -- rs/ethereum/ledger-suite-orchestrator
2f56f172a1 chore: bump rust to 1.89 (#6758)
b9221277cd chore: bumping edition to 2024 (#6715)
5c143d81fa feat: migrate to edition 2024 (#6667)
```

### Ledger Suite

The commit used
`e446c64d99a97e38166be23ff2bfade997d15ff7` corresponds to the [ICRC Ledger Suite release 2025-10-27](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-10-27).

#### Ledger

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2025-09-01..ledger-suite-icrc-2025-10-27 -- rs/ledger_suite/common rs/ledger_suite/icrc1/ledger rs/ledger_suite/icrc1/src rs/ledger_suite/icrc1/tokens_u256 packages/icrc-ledger-types
 7644b35479 feat(Ledgers): FI-1881: Check ledger liquid cycles balance before spawning archive (#7363)
 8c1dd9e122 chore(icrc-ledger-types): release version 0.1.12 of icrc-ledger-types (#7291)
 b358d80102 chore: upgrade rust: 1.89.0 -> 1.90.0 (#7322)
 aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
 d3f6d031b7 test(Ledgers): FI-1881: Add tests for archive spawning with cycles attached (#7221)
 fb4dff62d3 fix(icrc-ledger-types): FI-1866: Add try_from_subaccount_to_principal (#6911)
 2f56f172a1 chore: bump rust to 1.89 (#6758)
 3fccd4e885 refactor(Ledgers): FI-1530: Extract InMemoryLedger into separate crate (#6847)
 511b43918c chore(Ledgers): FI-1865: Simplify canister ID conversion (#6858)
 5ac0606166 chore(icrc-ledger-types): bump version with recent icrc21 types changes, update changelog (#6860)
 1a7ae4c615 refactor(Ledgers): FI-1529: Extract ledger suite StateMachine helpers into a separate crate (#6812)
 143ab585d5 refactor(Ledgers): FI-1814: Extract some consts into ic-ledger-suite-state-machine-tests-constants crate (#6733)
 b9221277cd chore: bumping edition to 2024 (#6715)
```

#### Index

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2025-09-01..ledger-suite-icrc-2025-10-27 -- rs/ledger_suite/icrc1/index-ng
 7644b35479 feat(Ledgers): FI-1881: Check ledger liquid cycles balance before spawning archive (#7363)
 aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
 89d0cecc05 feat(ICRC_Index): FI-1849: Add support for fees in mint and burn blocks (#6508)
 a50d51698f chore(Ledgers): Remove unused dependencies (#7012)
 2f56f172a1 chore: bump rust to 1.89 (#6758)
 1a7ae4c615 refactor(Ledgers): FI-1529: Extract ledger suite StateMachine helpers into a separate crate (#6812)
 7baf5eedf4 chore: bumping edition to follow workspace edition in leftover Cargo.toml (#6779)
 91f28f7e11 refactor(Ledger_suite): FI-1814: Move test_http_request_decoding_quota (#6729)
 b9221277cd chore: bumping edition to 2024 (#6715)
```

#### Archive

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2025-09-01..ledger-suite-icrc-2025-10-27 -- rs/ledger_suite/icrc1/archive/
 aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
 a50d51698f chore(Ledgers): Remove unused dependencies (#7012)
 2f56f172a1 chore: bump rust to 1.89 (#6758)
 91f28f7e11 refactor(Ledger_suite): FI-1814: Move test_http_request_decoding_quota (#6729)
 b9221277cd chore: bumping edition to 2024 (#6715)
 28de7a00e3 feat(ICRC-Archive): FI-1844: Ensure upgrade u64 <-> u256 fails (#6546)
```

## Upgrade args

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(
  variant {
    UpgradeArg = record {
      git_commit_hash = opt "e446c64d99a97e38166be23ff2bfade997d15ff7";
      ledger_compressed_wasm_hash = opt "15ec452faf00c40135b96a3ba0951ea13050e6e95e38cff249305462f81db62d";
      index_compressed_wasm_hash = opt "8df72887ab235f4533ee613b1bc7293ec8d62c866525b1425934cf992ef894a7";
      archive_compressed_wasm_hash = opt "3a0820cda687ee413f7f6b0d64199e2db125f17a8ea880918282b643f6c4cfa0";
    }
  },
)' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hashes of the gzipped WASMs for the ledger, index and archive match the proposed hashes in the upgrade arguments.

```
git fetch
git checkout e446c64d99a97e38166be23ff2bfade997d15ff7
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
