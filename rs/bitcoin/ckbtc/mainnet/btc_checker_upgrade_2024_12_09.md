# Proposal to upgrade the BTC Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `f901615f3daa36a5f3a9a6277140e1895ed53d2d`

New compressed Wasm hash: `f98790efff0bff952c922fbae5f2faa291ffd8c844a23b040158a858a262bd6a`

Upgrade args hash: `52d50d675b7e7791b17ab1af4b7505cb235d90490635efd554cd72827e81170e`

Target canister: `oltsj-fqaaa-aaaar-qal5q-cai`

Previous BTC Checker proposal: https://dashboard.internetcomputer.org/proposal/134413

---

## Motivation

Fix the problem of insufficent cycles supplied to https outcalls in the Bitcoin Checker canister, which should unblock the ckBTC minter.

## Upgrade args

```
git fetch
git checkout f901615f3daa36a5f3a9a6277140e1895ed53d2d
cd rs/bitcoin/checker
didc encode -d btc_checker_canister.did -t '(CheckArg)' '(variant { UpgradeArg = opt record { num_subnet_nodes = opt 34 } })' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 9849a2f03af855d09ac42f5949393c86df3d9c47..f901615f3daa36a5f3a9a6277140e1895ed53d2d -- rs/bitcoin/checker
f901615f3d fix(ckbtc): fix bitcoin checker cycle cost calculation (#3056)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout f901615f3daa36a5f3a9a6277140e1895ed53d2d
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-btc-checker.wasm.gz
```
