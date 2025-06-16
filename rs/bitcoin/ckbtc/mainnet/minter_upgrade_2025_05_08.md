# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `f8131bfbc2d339716a9cff06e04de49a68e5a80b`

New compressed Wasm hash: `78e06234358f6e6e067de9b9cfa0ce9e8193952a943f267986a84d90401aac01`

Upgrade args hash: `bd308dda17e56cd6abbacead803e1e1d313fcb42976904d153ed098e5c24bd81`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/135546

---

## Motivation

Upgrade the ckBTC minter to include the latest code changes, notably:

* Improve `update_balance` latency by caching `get_utxos` results. Set `get_utxos_cache_expiration_seconds` parameter to
  60 seconds.
* Increase concurrent BTC withdrawal request limit from 1,000 to 5,000.
* Add latency metric for `sign_with_ecdsa`.
* Allow `get_btc_address` calls from the anonymous principal.

## Release Notes

```
git log --format='%C(auto) %h %s' 177e28fa4427661462004a738d5ea83329b61f7e..f8131bfbc2d339716a9cff06e04de49a68e5a80b -- rs/bitcoin/ckbtc/minter
9204403648 feat(ckbtc): Add get_utxos_cache to reduce latency of update_balance calls (#4788)
12e4053d25 test(ckbtc): Add a test case when check_transaction returns NotEnoughCycles (#4832)
cb1f1f6ec4 feat(ckbtc): bump limit on concurrent withdrawals (#4804)
c90a650621 refactor(ckbtc): Clean up types used by ckbtc minter (#4757)
a6267fb8e1 feat(ckbtc): Allow get_btc_address calls from anonymous principal (#4743)
0c35125a00 chore(ckbtc): Add a canbench for event migration (#4029)
5daf1aefd1 fix(IDX): don't run //rs/bitcoin/ckbtc/minter:mainnet_events.mem.gz on MacOS x86_64 (#4313)
4d40e10c75 chore(IDX): use correct .gz name for canisters (#4300)
6bc4a95624 test(ckbtc): Add a test that replays mainnet events and dumps stable mem (#4240)
 ```

## Upgrade args

```
git fetch
git checkout f8131bfbc2d339716a9cff06e04de49a68e5a80b
didc encode -d rs/bitcoin/ckbtc/minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = opt record { get_utxos_cache_expiration_seconds = opt (60 : nat64) } })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout f8131bfbc2d339716a9cff06e04de49a68e5a80b
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```