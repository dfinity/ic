# Proposal to upgrade the ckBTC minter canister

Git hash: `667a6bd3bc08c58535b8b63bfebc01dba89c0704`

New compressed Wasm hash: `7938ee3c90ce51bdff77594f9f5153638207b838583b61b04c3166eaaf5a0ce7`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/130723

---

## Motivation

Update ckbtc-minter to includle the latest code changes, and most notably:

* Update `ic-cdk` dependency to patch a security issue.

Please note that there is no change to the KYT canister yet, as work is still under way.

## Upgrade args

```
git fetch
git checkout 667a6bd3bc08c58535b8b63bfebc01dba89c0704
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant {Upgrade})'
```

## Release Notes

```
git log --format=%C(auto) %h %s cbeffcfb8cce30c96a6e688986fd37a9564690c1..667a6bd3bc08c58535b8b63bfebc01dba89c0704 -- rs/bitcoin/ckbtc/minter
667a6bd3b feat: add a metric to track the total memory usage of XC-canisters (#1050)
ca24b5d66 chore: sort dependencies in Cargo.toml files (#828)
ce39387af feat(ckbtc): import code from btc-tx-input-canister as the new kyt canister XC-150 (#791)
b4be567dc chore: Bump rust version to 1.80 (#642)
14f088b87 chore(IDX): set wasm paths via env (#483)
576bb8d17 chore: add buildifier sort comment to Bazel files
f609ec05a feat(PocketIC): IC mainnet-like ECDSA support in PocketIC
7c6d7f37e chore(IDX): align cargo & bazel deps
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 667a6bd3bc08c58535b8b63bfebc01dba89c0704
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
