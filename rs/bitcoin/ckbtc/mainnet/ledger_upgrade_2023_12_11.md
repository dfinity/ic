# Proposal to Upgrade the ckBTC Ledger Canister

Git hash: `6a8e5fca2c6b4e12966638c444e994e204b42989`

New compressed Wasm hash: `34f75f7598fcb0f22c9481bb47308687f8592b4891bf469f792ee2399abefc77`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/125587

---

## Motivation

Fixes a bug in the ledger where the `spender` field in burn blocks was incorrectly set to `null`.
This incorrect behaviour can for example be observed in past withdrawals to convert back ckBTC to BTC.
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
$ git log --format="%C(auto) %h %s" 24fd80082f40de6d0b3cd7876be09ef1aadbde86..6a8e5fca2c6b4e12966638c444e994e204b42989  rs/rosetta-api/icrc1/ledger
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
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```