# Proposal to upgrade the ckDOGE minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `50ba5020d6d654d70a48d964969fef8443fb42ae`

New compressed Wasm hash: `02b4382005cdfd8503cee45af22d94e00c3b07ef183d2012b876bbec97f8b020`

Upgrade args hash: `7e30374ea4b40297f147e4a8f60ea17f16f90f182807701386e7e4d3357fe693`

Target canister: `eqltq-xqaaa-aaaar-qb3vq-cai`

Previous ckDOGE minter proposal: https://dashboard.internetcomputer.org/proposal/143936

---

## Motivation

Deactivate minting of ckDOGE by setting the minter's operation mode to `DepositsRestrictedTo` with an empty allow list.

In this mode, every call to `update_balance` is rejected with `TemporarilyUnavailable`, so no new DOGE deposits are converted to ckDOGE. Withdrawals (converting ckDOGE back to DOGE via `retrieve_doge_with_approval`) are not affected and remain available to everyone.

Minting can be reactivated later by a new upgrade proposal that sets the mode back to `GeneralAvailability`.

## Release Notes

This proposal does not change the code of the minter: it reinstalls the currently deployed Wasm (see proposal [141773](https://dashboard.internetcomputer.org/proposal/141773)), only with new upgrade arguments.

## Upgrade args

```
git fetch
git checkout 50ba5020d6d654d70a48d964969fef8443fb42ae
didc encode -d rs/dogecoin/ckdoge/minter/ckdoge_minter.did -t '(MinterArg)' '(variant { Upgrade = opt record { mode = opt variant { DepositsRestrictedTo = vec {} } } })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 50ba5020d6d654d70a48d964969fef8443fb42ae
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckdoge-minter.wasm.gz
```
