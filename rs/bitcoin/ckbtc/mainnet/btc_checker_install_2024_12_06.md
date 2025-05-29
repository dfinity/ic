# Proposal to install the Bitcoin Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `9849a2f03af855d09ac42f5949393c86df3d9c47`

New compressed Wasm hash: `455f2e7a2a1b872b59c7dc6729f77f507ab4c4617be402d791c9e79ec55bf6d4`

Install args hash: `4bf28e4112db80ce139abc509a4178a6790582566a5c64c5fe2ad009b4173133`

Target canister: `oltsj-fqaaa-aaaar-qal5q-cai`

---

## Motivation

Install the Bitcoin Checker canister at canister id `oltsj-fqaaa-aaaar-qal5q-cai`.

The Bitcoin Checker implements checks for Bitcoin transactions and addresses against the OFAC (https://sanctionssearch.ofac.treas.gov/) list.
It offers a more transparent approach than the KYT canister, and helps to simplify the process.
A follow-up NNS proposal will propose to switch the ckBTC minter to using the Bitcoin Checker.

More discussions on this change can be found in the forum thread https://forum.dfinity.org/t/ckbtc-and-kyt-compliance/18754.

## Install args

```
git fetch
git checkout 9849a2f03af855d09ac42f5949393c86df3d9c47
cd rs/bitcoin/checker
didc encode -d btc_checker_canister.did -t '(CheckArg)' '(variant { InitArg = record { btc_network = variant { mainnet }; check_mode = variant { Normal }; } })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 9849a2f03af855d09ac42f5949393c86df3d9c47
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-btc-checker.wasm.gz
```
