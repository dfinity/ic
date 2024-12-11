# Proposal to upgrade the BTC Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c58e00fe2271d77ede9ccab5a6b317689859ea98`

New compressed Wasm hash: `1e174def478e8324f025eda7f4d723dc76638ed2a1200a3de934850c6ec1da9b`

Upgrade args hash: `1115f49331a1f7e6fddbcab23cdc8932508c193782fa42d80579a19981fe211f`

Target canister: `oltsj-fqaaa-aaaar-qal5q-cai`

Previous BTC Checker proposal: https://dashboard.internetcomputer.org/proposal/134442

---

## Motivation

Upgrade the Bitcoin Checker canister to fix errors when making RPC https calls over http/2 and improve usability.

## Upgrade args

```
git fetch
git checkout c58e00fe2271d77ede9ccab5a6b317689859ea98
cd rs/bitcoin/checker
didc encode -d btc_checker_canister.did -t '(CheckArg)' '(variant { UpgradeArg = null })' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' f901615f3daa36a5f3a9a6277140e1895ed53d2d..c58e00fe2271d77ede9ccab5a6b317689859ea98 -- rs/bitcoin/checker
c58e00fe22 fix(ckbtc): Drop Host header from https outcall request (#3115)
57362c30e3 fix(ckbtc): state schema upgrade (#3071)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c58e00fe2271d77ede9ccab5a6b317689859ea98
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-btc-checker.wasm.gz
```
