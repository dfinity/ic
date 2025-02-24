# Proposal to upgrade the ckBTC minter canister and reduce minimum retrieval amount

Repository: `https://github.com/dfinity/ic.git`

Git hash: `511ad1cf505003e33baf0ce0eefa0168aad91bf1`

New compressed Wasm hash: `638d972cf20cfd725fadb7e49957eceadb0bee85bbc711f96d5d5be541e8e091`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/133057

---

## Motivation

Reduce the minimum ckbtc retrieval amount to 0.0005 BTC, as proposed by a recently passed motion proposal https://dashboard.internetcomputer.org/proposal/133462.

## Upgrade args

```
git fetch
git checkout 511ad1cf505003e33baf0ce0eefa0168aad91bf1
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant {Upgrade = opt record { retrieve_btc_min_amount = opt 50000 }})' | xxd -r -p | sha256sum
```

## Release Notes

There is no change to the deployed Wasm binary.

The same version was deployed previously in https://dashboard.internetcomputer.org/proposal/133057.


## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 511ad1cf505003e33baf0ce0eefa0168aad91bf1
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
