# Proposal to upgrade the ckBTC minter canister

Git hash: `cbeffcfb8cce30c96a6e688986fd37a9564690c1`

New compressed Wasm hash: `514fb0645fbfab0dd1f74de297277924c85e845048c8ffa82a1b794d64adb71f`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/130096

---

## Motivation

This proposal upgrades the ckBTC minter to support pagination in its dashboard HTML page, with no significant change affecting other parts of the minter.

## Upgrade args

```
git fetch
git checkout cbeffcfb8cce30c96a6e688986fd37a9564690c1
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant {Upgrade})'
```

## Release Notes

```
git log --format=%C(auto) %h %s d1504fc4265703c5c6a73098732a4256ea8ff6bf..cbeffcfb8cce30c96a6e688986fd37a9564690c1 -- rs/bitcoin/ckbtc/minter
c549e32a8 chore: upgrade crates and use workspace versions
695a0affa chore: Bump rust version to 1.78
a5c8d79ad feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
36881617c chore(ckbtc): Add pagination to ckbtc minter dashboard XC-39
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout cbeffcfb8cce30c96a6e688986fd37a9564690c1
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
