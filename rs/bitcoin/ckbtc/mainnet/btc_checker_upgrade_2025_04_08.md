# Proposal to upgrade the BTC Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `eecacca6c05871f00e674dcc4bfcf548fa0c2f63`

New compressed Wasm hash: `ed564a757ca16048b520caae0d03501914ae7f99f23044bfdb602860ead4d4a2`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `oltsj-fqaaa-aaaar-qal5q-cai`

Previous BTC Checker proposal: https://dashboard.internetcomputer.org/proposal/135548

---

## Motivation

The previous BTC Checker upgrade failed due to mismatching upgrade argument.

This upgrade contains notable changes, including those from the previous upgrade: 

* Update the OFAC checklist
* Add new `check_transaction_query` and `check_transaction_str` methods. 
* Make canister init/upgrade argument optional

## Release Notes

```
git log --format='%C(auto) %h %s' c58e00fe2271d77ede9ccab5a6b317689859ea98..eecacca6c05871f00e674dcc4bfcf548fa0c2f63 -- rs/bitcoin/checker
a121d18e91 feat(ckbtc): Make bitcoin checker's init argument optional (#4684)
ddcdb2e92f chore: Remove last management canister types from PocketIC and its users (#4178)
fe1db07381 chore(ckbtc): update OFAC checklist (#4084)
810eeb14ca chore: use cdk::api::in_replicated_execution (#3949)
8dc1b0d253 chore(ckbtc): add check_transaction_query method to Bitcoin checker (#3454)
967fe21189 chore: bitcoin crate upgrade (#3080)
841793d547 chore: add MetricsAssert test utility (#3375)
2c79ddcfd8 feat(PocketIC): new call response types (#3425)
fa6a0783a8 chore(ckbtc): improve Bitcoin Checker metrics and tests (#3228)
7136d8b228 fix(ckbtc): Add num_subnet_nodes to Bitcoin Checker's InitArg (#3075)
eb61ab2449 refactor(ckbtc/cketh): unify blocklist (#2947)
d4fce48e9c feat(ckbtc): add check_transaction_str to Bitcoin Checker (#3212)
f102d72545 fix(ckbtc): btc-checker charges service fee before checking txid (#3191)
 ```

## Upgrade args

```
git fetch
git checkout eecacca6c05871f00e674dcc4bfcf548fa0c2f63
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout eecacca6c05871f00e674dcc4bfcf548fa0c2f63
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-btc-checker.wasm.gz
```
