# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c741e349451edf0c9792149ad439bb32a0161371`

New compressed Wasm hash: `cf9dd8805aa34a385151aa962246c871f36453ab2c38dec4b9d15295570cec26`

Upgrade args hash: `9dfa9db8b0ddd5f32c0680ff28b98411f1066407aafad00f90d3bd71b9ad9c04`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/134357

---

## Motivation

Upgrade all ledger suites managed by the orchestrator to the latest
version ([ledger-suite-icrc-2025-01-07](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-01-07)) to
continue the migration towards stable memory.

## Upgrade args

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "c741e349451edf0c9792149ad439bb32a0161371"; ledger_compressed_wasm_hash = opt "8b2e3e596a147780b0e99ce36d0b8f1f3ba41a98b819b42980a7c08c309b44c1"; index_compressed_wasm_hash = opt "d21d059962144c835c8b291af3033e1f1c835af2350a5cd92b3cf8d687a1a7be"; archive_compressed_wasm_hash = opt "d2170c173f814fafc909737ec82f098714d44aa98ebd4f6dbf4e175160e1200f"}})' | xxd -r -p | sha256sum
```

## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ethereum/ledger-suite-orchestrator
c741e34945 feat: ICRC-ledger: FI-1439: Implement V4 for ICRC ledger - migrate balances to stable structures (#2901)
484a58d15c test(cketh): end-to-end test with `foundry` (#3014)
642b305524 feat(cketh/ckerc20): Display upgrades on dashboard (#3009)
2456414f7a fix: Use workspace rust edition instead of specifying it in the Cargo.toml file (#3049)
 ```

### Ledger Suite

The commit used `c741e349451edf0c9792149ad439bb32a0161371` corresponds to
the [ICRC Ledger Suite release 2025-01-07](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-01-07).

### Ledger

```
git log --format="%C(auto) %h %s" 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ledger_suite/icrc1/ledger
c741e34945 feat: ICRC-ledger: FI-1439: Implement V4 for ICRC ledger - migrate balances to stable structures (#2901)
ddadaafd51 test(ICP_Ledger): FI-1616: Fix ICP ledger upgrade tests (#3213)
dfc3810851 fix(ICRC-Ledger): changed certificate version (#2848)
b006ae9934 feat(ICP-ledger): FI-1438: Implement V3 for ICP ledger - migrate allowances to stable structures (#2818)
```

### Index

```
git log --format="%C(auto) %h %s" 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ledger_suite/icrc1/index-ng
c741e34945 feat: ICRC-ledger: FI-1439: Implement V4 for ICRC ledger - migrate balances to stable structures (#2901)
575ca531a7 chore(ICRC_Index): FI-1468: Remove old ICRC index canister (#3286)
8d4fcddc6e test(ICRC_Index): FI-1617: Optimize retrieve_blocks_from_ledger_interval tests (#3236)
e369646b76 fix: Use default rust edition instead of specifying it in the BUILD rules (#3047)
```

### Archive

No changes since last version (`2190613d3b5bcd9b74c382b22d151580b8ac271a`).

```
git log --format="%C(auto) %h %s" 2190613d3b5bcd9b74c382b22d151580b8ac271a..c741e349451edf0c9792149ad439bb32a0161371 -- rs/ledger_suite/icrc1/archive
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger, index and archive match the proposed hash.

```
git fetch
git checkout c741e349451edf0c9792149ad439bb32a0161371
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```
