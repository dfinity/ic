# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `7360f8f35bda2e4754bb7f2258d6852feec268e8`

New compressed Wasm hash: `b8bb51fe0fd93bcb262a2e61e13a3c1625496e7e8cc55c0c635e8536a4096680`

Upgrade args hash: `0987f8cdde68719fa7de404958ef92341515d317f7b643492d6b2bff4ce36285`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/143606

---

## Motivation

Effectively disable block archiving on all ledgers managed by the orchestrator, by raising the archiving trigger threshold to `4_200_000_000` blocks. The Wasm module of each ledger is not changed and remains at the currently deployed version from proposal [140856](https://dashboard.internetcomputer.org/proposal/140856).

## Release Notes

```
git log --format='%C(auto) %h %s' cf41372e3d4dc1accfe2c09a7969f8bddc729dc1..7360f8f35bda2e4754bb7f2258d6852feec268e8 -- rs/ethereum/ledger-suite-orchestrator
957dcaf50b feat(ledger-suite-orchestrator): forward ledger upgrade argument to managed ledgers (#11407)
6ca30003de feat: migrate to ic-cdk 0.20 (#11069)
53efbe5878 test(cketh): migrate integration tests to PocketIC (#10955)
04a1d9ebcc test(ledger-suite-orchestrator): migrate integration tests to PocketIC (#10949)
6ed0116324 chore: move all crate definitions into workspace (#10812)
f245d740fb chore: use workspace crates everywhere (#10809)
5297f59ed2 chore: prepare for rustc version bump to v1.95.0 (#10637)
b44af81463 chore(defi): remove deprecated ic-cdk imports in ic-ledger-suite-orchestrator (#10291)
63b841f4fa chore: remove unused DeFi rust dependencies (#10281)
7fb12c2e43 ci(defi): check endpoints exported in a canister's WASM against its Candid specification (#10147)
88a0df635a chore(icrc-ledger-types): DEFI-1894: Switch icrc-ledger-types bazel variants (#9900)
d3b3351fa3 feat(icrc1): implement ICRC-122/152 with ledger endpoints, index-ng, and Rosetta support (#9586)
b608c374f2 chore: 42u64 -> 42_u64 (#9523)
a08eb494fe chore(de-fi): Add separator before type suffix in integer literals. (#9433)
cca3eb1c44 refactor: Group cycles related types in new ic-types-cycles crate (#9341)
 ```

## Upgrade args

```
git fetch
git checkout 7360f8f35bda2e4754bb7f2258d6852feec268e8
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record { ledger_compressed_wasm_hash = opt "390e22377640748f5a63fc35d50680d27a05d3e9a05c1c25c4061cacebda4c56"; ledger_upgrade_arg = opt record { change_archive_options = opt record { trigger_threshold = opt 4_200_000_000 : opt nat64 } } } })' | xxd -r -p | sha256sum
```

* The ledger compressed wasm hash `390e22377640748f5a63fc35d50680d27a05d3e9a05c1c25c4061cacebda4c56` is the same as the currently deployed version from proposal [140856](https://dashboard.internetcomputer.org/proposal/140856).
* Raising the archiving trigger threshold to `4_200_000_000` blocks effectively disables block archiving on all ledgers managed by the orchestrator.

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7360f8f35bda2e4754bb7f2258d6852feec268e8
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
