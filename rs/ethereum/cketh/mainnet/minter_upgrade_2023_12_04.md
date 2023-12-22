# Proposal to Upgrade the ckETH Minter Canister

Git hash: `51d01d3936498d4010de54505d6433e9ad5cc62b`

New compressed Wasm hash: `4451498cd1bfbcdce95d99392774459c71ded0a792625a882c153c37840c2394`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/126171

---

## Motivation

One of the 3 Ethereum JSON-RPC providers that the ckETH minter uses to interact with the Ethereum blockchain is Cloudflare, which limits the range of blocks that can be queried with a single `eth_getLogs` request to [800](https://developers.cloudflare.com/web3/ethereum-gateway/reference/supported-api-methods/). This upgrade corrects a bug in the parameter `MAX_BLOCK_SPREAD` which results in trying to fetch the logs for 801 blocks when the minter tries to catch up with the latest finalized Ethereum block, which results in errors from Cloudflare.

## Upgrade args

```
git fetch
git checkout 51d01d3936498d4010de54505d6433e9ad5cc62b
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {} })'
```

## Release Notes

```
git log --format="%C(auto) %h %s" 5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576..51d01d3936498d4010de54505d6433e9ad5cc62b -- rs/ethereum/cketh/minter
 51d01d3936 fix(cketh): query logs for a block range of at most 799 blocks due to Cloudflare
 7ff51f25fa chore(cketh): update the block size expectation for staging
 039d730112 feat(cketh): add metric `cketh_minter_stable_memory_bytes
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 51d01d3936498d4010de54505d6433e9ad5cc62b
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
