# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `744f4683df2ca79f5f537b3db48a1c03d4ff084e`

New compressed Wasm hash: `f8d82d7bad3e7d6b8d36c04936d3aa6a67190250bf456710c9fcd7da39926d6c`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/134414

---

## Motivation

Update the ckBTC minter to include the latest code changes, notably:
* Add metrics for the `update_latency` method.
* Add timestamps to the minter events. 

## Upgrade args

```
git fetch
git checkout 744f4683df2ca79f5f537b3db48a1c03d4ff084e
cd rs/bitcoin/ckbtc/minter
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 9849a2f03af855d09ac42f5949393c86df3d9c47..744f4683df2ca79f5f537b3db48a1c03d4ff084e -- rs/bitcoin/ckbtc/minter
841793d547 chore: add MetricsAssert test utility (#3375)
cfd1859fd8 chore(ckbtc): remove distribute_kyt_fee and reimburse_failed_kyt (#3325)
72a1f85c9f chore(ckbtc): property tests for event serialization and deserialization (#3277)
9afadc4a78 chore(ckbtc): add optional timestamp to minter events (#3157)
7136d8b228 fix(ckbtc): Add num_subnet_nodes to Bitcoin Checker's InitArg (#3075)
db8c33d181 chore(ckbtc): add metrics for the latency of `update_balance` in the minter (#3003)
f901615f3d fix(ckbtc): fix bitcoin checker cycle cost calculation (#3056)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 744f4683df2ca79f5f537b3db48a1c03d4ff084e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
