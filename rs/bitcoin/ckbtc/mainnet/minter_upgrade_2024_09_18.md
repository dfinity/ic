# Proposal to upgrade the ckBTC minter canister

Git hash: `511ad1cf505003e33baf0ce0eefa0168aad91bf1`

New compressed Wasm hash: `638d972cf20cfd725fadb7e49957eceadb0bee85bbc711f96d5d5be541e8e091`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/132134

---

## Motivation
Since the size of the fiduciary subnet (`pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`) increased from 28 nodes to 31 (proposal [132483](https://dashboard.internetcomputer.org/proposal/132483)), and should soon be increased to 34, the cycles cost of a t-ECDSA signature increased proportionally and needs to be updated.

## Upgrade args

```
git fetch
git checkout 511ad1cf505003e33baf0ce0eefa0168aad91bf1
cd rs/bitcoin/ckbtc/minter
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' 667a6bd3bc08c58535b8b63bfebc01dba89c0704..511ad1cf505003e33baf0ce0eefa0168aad91bf1 -- rs/bitcoin/ckbtc/minter
511ad1cf5 fix(cketh/ckbtc): Update fee for tECDSA signatures (#1545)
4d09678d2 chore: sort rust derive traits (#1241)
d4c3bb26c chore: upgrade crates and use workspace version (#1207)
3fc6c3fda chore: Remove use of extended_bip32 crate from ckbtc minter (#976)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 511ad1cf505003e33baf0ce0eefa0168aad91bf1
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
