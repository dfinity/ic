# Proposal to Upgrade the ckETH Ledger Canister

Git hash: `6a8e5fca2c6b4e12966638c444e994e204b42989`

New compressed Wasm hash: `8454cb98353ffe437933f3b1e89c7496b573a30c5731852c4d037461dc0ca9cc`

Target canister: `ss2fx-dyaaa-aaaar-qacoq-cai`

Previous ckETH ledger proposal: https://dashboard.internetcomputer.org/proposal/126309

---

## Motivation

Fixes a bug in the ledger where the `spender` field in burn blocks was incorrectly not set.
This incorrect behaviour can for example be observed in past withdrawals to convert back ckETH to ETH.
Index and archive canisters are not affected.

## Upgrade args

```
git fetch
git checkout 6a8e5fca2c6b4e12966638c444e994e204b42989
cd rs/rosetta-api/icrc1/ledger
didc encode -d ledger.did -t '(LedgerArg)' '(variant {Upgrade})'
```

## Release Notes

```
git log --format="%C(auto) %h %s" 5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576..6a8e5fca2c6b4e12966638c444e994e204b42989 -- rs/rosetta-api/icrc1/ledger
 1446a38f1a fix(icrc1_ledger): include spender in Burn block
 d0de801df7 Merge branch 'sat-bazel-crates-version-bump' into 'master'
 a163262f11 chore(release): Bump up the bazel versions for all crates as well
 70df46734c fix(icrc1-ledger): set certified data on init
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 6a8e5fca2c6b4e12966638c444e994e204b42989
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
```
