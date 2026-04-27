# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `cf41372e3d4dc1accfe2c09a7969f8bddc729dc1`

New compressed Wasm hash: `b7294354c6ad8d0466894204471155d47e80af468fbca4759baa64c7c77ca65a`

Upgrade args hash: `2c0a6655a48e343f2514e9f3bd379a3e62dee2d966a6f19699c06a83242cd76f`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/140272

---

## Motivation
Upgrade all ledger suites managed by the orchestrator to the latest version ([ledger-suite-icrc-2026-03-09](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-03-09)).


## Release Notes

### Orchestrator

```
git log --format='%C(auto) %h %s' 653c927f2c732398bfd6e6b9dbfaf983cfb9b911..cf41372e3d4dc1accfe2c09a7969f8bddc729dc1 -- rs/ethereum/ledger-suite-orchestrator
c199eff5ab feat(ICRC_Index): DEFI-2684: Variable build_index wait time (#9060)
 ```

### Ledger Suite

The commit used
`cf41372e3d4dc1accfe2c09a7969f8bddc729dc1` corresponds to the [ICRC Ledger Suite release 2026-03-09](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc
-2026-03-09).

#### Ledger

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2026-02-02..ledger-suite-icrc-2026-03-09 -- rs/ledger_suite/common rs/ledger_suite/icrc1/ledger
rs/ledger_suite/icrc1/src rs/ledger_suite/icrc1/tokens_u256 packages/icrc-ledger-types
 b34d5ed28c chore: Upgrade rustc to 1.93.1  (#9113)
 11306dd454 chore: always add canbench test (#9151)
 8910873dcc chore: bump candid to v0.10.22 (#8780)
```

#### Index

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2026-02-02..ledger-suite-icrc-2026-03-09 -- rs/ledger_suite/icrc1/index-ng
 c199eff5abb feat(ICRC_Index): DEFI-2684: Variable build_index wait time (#9060)
```

#### Archive

```
git log --format="%C(auto) %h %s" ledger-suite-icrc-2026-02-02..ledger-suite-icrc-2026-03-09 -- rs/ledger_suite/icrc1/archive/

```

## Upgrade args

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(
  variant {
    UpgradeArg = record {
      git_commit_hash = opt "cf41372e3d4dc1accfe2c09a7969f8bddc729dc1";
      ledger_compressed_wasm_hash = opt "390e22377640748f5a63fc35d50680d27a05d3e9a05c1c25c4061cacebda4c56";
      index_compressed_wasm_hash = opt "b9f248fed399250f17bd3c00386c251bdff5479001bedde341aeccc632a74253";
      archive_compressed_wasm_hash = opt "47c385eda3cfa2816e9da29b570ce69beda49770916a7745c7a3cfda0ccdc2f3";
    }
  },
)' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hashes of the gzipped WASMs for the ledger, index and archive match the proposed hashes in the upgrade arguments.

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
