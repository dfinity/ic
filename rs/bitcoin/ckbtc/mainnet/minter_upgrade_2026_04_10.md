# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `ebb18a0983f28f1882b9957e99f072695f43141e`

New compressed Wasm hash: `3801f9e7751d42f1ea2ff9b777d61ae85cdcf85fc13a3208c5250dbd803e87a5`

Upgrade args hash: `abf6b9f54bb94025c0aff10c4eb05e182118052d6c7a490c2aa50ea651ed7d23`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/140956

---

## Motivation

* Add an additional measure to protect against and alert about double-minting of cached UTXOs.


## Release Notes

```
git log --format='%C(auto) %h %s' 00b276124eacd236b379f09322064c602fcfe9e2..ebb18a0983f28f1882b9957e99f072695f43141e -- rs/bitcoin/ckbtc/minter
a22189c20d fix(ckbtc): prevent double-mint of cached UTXOs after transaction finalization (#9596)
675a14c1af test(defi): move event files to CDN (#9563)
b608c374f2 chore: 42u64 -> 42_u64 (#9523)
 ```

## Upgrade args

```
git fetch
git checkout ebb18a0983f28f1882b9957e99f072695f43141e
didc encode -d rs/bitcoin/ckbtc/minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout ebb18a0983f28f1882b9957e99f072695f43141e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
