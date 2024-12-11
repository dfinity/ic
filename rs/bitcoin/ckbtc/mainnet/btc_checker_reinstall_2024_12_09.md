# Proposal to install the BTC Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `f901615f3daa36a5f3a9a6277140e1895ed53d2d`

New compressed Wasm hash: `f98790efff0bff952c922fbae5f2faa291ffd8c844a23b040158a858a262bd6a`

Install args hash: `29347cf64bcf5fdf3e55aaa225583f2d5ccc3e899b519d465d4786c2bdb162cf`

Target canister: `oltsj-fqaaa-aaaar-qal5q-cai`

Previous BTC Checker proposal: https://dashboard.internetcomputer.org/proposal/134413

---

## Motivation

The previous upgrade proposal failed due to an upgrade compatibility problem.
This fixes it by reinstalling the Bitcoin Checker canister using the same wasm hash as in the previous upgrade proposal.

## Install args

```
git fetch
git checkout f901615f3daa36a5f3a9a6277140e1895ed53d2d
cd rs/bitcoin/checker
didc encode -d btc_checker_canister.did -t '(CheckArg)' '(variant { InitArg = record { btc_network = variant { mainnet }; check_mode = variant { Normal }; } })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout f901615f3daa36a5f3a9a6277140e1895ed53d2d
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-btc-checker.wasm.gz
```
