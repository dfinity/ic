# Proposal to upgrade the ckDOGE ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `cf41372e3d4dc1accfe2c09a7969f8bddc729dc1`

New compressed Wasm hash: `390e22377640748f5a63fc35d50680d27a05d3e9a05c1c25c4061cacebda4c56`

Upgrade args hash: `24625928c7f095e298e75e821b69e117baca30508bf2239322d7634a99d7a82f`

Target canister: `efmc5-wyaaa-aaaar-qb3wa-cai`

Previous ckDOGE ledger proposal: https://dashboard.internetcomputer.org/proposal/140952

---

## Motivation

Effectively disable block archiving on the ckDOGE ledger, by raising the archiving trigger threshold to
4_200_000_000 blocks. The Wasm module is not changed: the hash above is the hash of the module
this canister is already running. The sole effect of this proposal is the upgrade argument.

## Release Notes

```
The Wasm module is unchanged by this proposal. The proposed module hash
390e22377640748f5a63fc35d50680d27a05d3e9a05c1c25c4061cacebda4c56
is identical to the module hash currently running on `efmc5-wyaaa-aaaar-qb3wa-cai`, and is built from
cf41372e3d4dc1accfe2c09a7969f8bddc729dc1, the same commit the canister was last upgraded to. There are therefore no code changes to
report.
```

## Upgrade args

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
didc encode -d rs/ledger_suite/icrc1/ledger/ledger.did -t '(LedgerArg)' '(variant { Upgrade = opt record { change_archive_options = opt record { trigger_threshold = opt (4_200_000_000 : nat64); }; } })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
```
