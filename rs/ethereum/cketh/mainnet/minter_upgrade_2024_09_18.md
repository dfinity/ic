# Proposal to upgrade the ckETH minter canister

Git hash: `511ad1cf505003e33baf0ce0eefa0168aad91bf1`

New compressed Wasm hash: `b09dafaaa92efa5fffa831104fc39ecc759fb6954cfa8615dc00b77700d37a68`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/132474

---

## Motivation
Since the size of the fiduciary subnet (`pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`) increased from 28 nodes to 31 (proposal [132483](https://dashboard.internetcomputer.org/proposal/132483)), and should soon be increased to 34, the cycles cost of a t-ECDSA signature increased proportionally and needs to be updated.


## Upgrade args

```
git fetch
git checkout 511ad1cf505003e33baf0ce0eefa0168aad91bf1
cd rs/ethereum/cketh/minter
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' 603473e2a9d4f5a0259bc4ea6aee4ba438186fba..511ad1cf505003e33baf0ce0eefa0168aad91bf1 -- rs/ethereum/cketh/minter
511ad1cf5 fix(cketh/ckbtc): Update fee for tECDSA signatures (#1545)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 511ad1cf505003e33baf0ce0eefa0168aad91bf1
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
