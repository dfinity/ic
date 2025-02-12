# Proposal to upgrade the ckBTC minter canister

Repository: `git@github.com:dfinity/ic-private.git`

Git hash: `41cba4e8db84de1cc79c26ddf7377b52e41de30a`

New compressed Wasm hash: `ece9b7e0b7565071461cba2e67c823821c5423c818066b32d0b9fae314296d51`

Upgrade args hash: `445734292959382834da46c68370d87f8117d50271f6b8a97d5eb8dadac8cb94`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/135200

---

## Motivation

Fix a potential vulnerability in ckBTC minter that was discovered during an internal security review.

## Upgrade args

```
git fetch
git checkout 41cba4e8db84de1cc79c26ddf7377b52e41de30a
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 41cba4e8db84de1cc79c26ddf7377b52e41de30a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
