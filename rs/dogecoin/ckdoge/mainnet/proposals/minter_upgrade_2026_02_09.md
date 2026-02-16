# Proposal to upgrade the ckDOGE minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `79cbc4b37c116e8fb75e26dc3eeb4e2bcf13e037`

New compressed Wasm hash: `f64022f90536d3770f6881adf10cbb748963ac9d57f7baaf4e8b63d1bd7c2807`

Upgrade args hash: `1451fbf85e08ec5c9e4385beae21168934368e260e480ceb15397cc96c2c6903`

Target canister: `eqltq-xqaaa-aaaar-qb3vq-cai`

Previous ckDOGE minter proposal: https://dashboard.internetcomputer.org/proposal/140183

---

## Motivation

This proposal aims to reduce the time it takes for a DOGE withdrawal to be processed by the ckDOGE minter by reducing the max time a transaction spends in the queue before being sent to the Dogecoin network from 10 minutes to 1 minute, corresponding to Dogecoin's expected block time.


## Release Notes

```
git log --format='%C(auto) %h %s' 990e96bf57d4abacddab0b34f0a0ec9e8c31ee0f..79cbc4b37c116e8fb75e26dc3eeb4e2bcf13e037 -- rs/dogecoin/ckdoge/minter
8b749ab7c4 docs(ckdoge): Document deposit and withdrawal flows (#8647)
 ```

## Upgrade args

```
git fetch
git checkout 79cbc4b37c116e8fb75e26dc3eeb4e2bcf13e037
didc encode -d rs/dogecoin/ckdoge/minter/ckdoge_minter.did -t '(MinterArg)' '(variant { Upgrade = opt record { max_time_in_queue_nanos = opt (60_000_000_000 : nat64) } })' | xxd -r -p | sha256sum
```

About the upgrade argument:

- max_time_in_queue_nanos: The maximum time a Dogecoin transaction spends in the queue before being sent is set to one minute, or 60 billion nanoseconds.

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 79cbc4b37c116e8fb75e26dc3eeb4e2bcf13e037
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckdoge-minter.wasm.gz
```