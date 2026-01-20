# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `61d605fd75c61072bfeed9a61adf7eca2b8dca5f`

New compressed Wasm hash: `0c225b61b9473d57355792cc7a5108e3df0dfb2d5d8dd1c22e31079ed747aecb`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/139664

---

## Motivation

Upgrade the ckBTC minter canister to start the periodic consolidation of the set of UTXOs:
 * Currently, the minter has too many UTXOS of small value: it has around 60k UTXOs for a total of around 385 BTC.
 * This is a problem for large withdrawal requests (ckBTC -> BTC) involving typically more than 10 BTC, since a transaction created by the minter to cover the total withdrawal amount may need such a large number of inputs that the transaction becomes non-standard. As a stop-gap solution, proposal [137930](https://dashboard.internetcomputer.org/proposal/137930) limited the number of inputs in a transaction to 1000.
 * On the other hand, the minter needs to have sufficiently many UTXOs to be able to serve multiple withdrawal requests in parallel.
 * Simulations have shown that the sweet spot for the minter is around 10k UTXOs.

To reach that number, the minter will do successive rounds of (initially) daily consolidations, where one round involves:
* Creating a transaction with 1000 inputs using 1000 UTXOs with the smallest value and 2 outputs with similar value back to the minter's address.
* Paying the Bitcoin transaction fee from the ledger fee collector account.


## Release Notes

```
git log --format='%C(auto) %h %s' d13be5a27b3331c4dc8831593eed0e3ec08b260f..61d605fd75c61072bfeed9a61adf7eca2b8dca5f -- rs/bitcoin/ckbtc/minter
61d605fd75 feat(ckbtc): consolidate small value UTXOs periodically (#7891)
37e6df7dd3 perf(ckbtc): avoid cloning the UTXOs set in `estimate_withdrawal_fee` (#7974)
 ```

## Upgrade args

```
git fetch/
git checkout 61d605fd75c61072bfeed9a61adf7eca2b8dca5f
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 61d605fd75c61072bfeed9a61adf7eca2b8dca5f
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
