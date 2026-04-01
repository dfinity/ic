# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `00b276124eacd236b379f09322064c602fcfe9e2`

New compressed Wasm hash: `83674bf178a41356c43b96cffd63f5bbe13545dfc3777fdfdd6f3ffc6848be31`

Upgrade args hash: `abf6b9f54bb94025c0aff10c4eb05e182118052d6c7a490c2aa50ea651ed7d23`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/140929

---

## Motivation

Due to the security incident explained in this [forum post](https://forum.dfinity.org/t/proposal-140929-to-upgrade-the-ckbtc-minter/65401/3), the following ckBTC withdrawals (ckBTC -> BTC) are currently stuck:

* [3459007](https://dashboard.internetcomputer.org/bitcoin/transaction/3459007), [3459009](https://dashboard.internetcomputer.org/bitcoin/transaction/3459009), and [3459013](https://dashboard.internetcomputer.org/bitcoin/transaction/3459013) because the transaction from the minter tries to reuse the already spent output [`91bb46443799335076fbcd117f2295c7499d02dd3a59c22a531d31591114b303:5`](https://mempool.space/tx/91bb46443799335076fbcd117f2295c7499d02dd3a59c22a531d31591114b303#vout=5).
* [3489347](https://dashboard.internetcomputer.org/bitcoin/transaction/3489347) and [3489353](https://dashboard.internetcomputer.org/bitcoin/transaction/3489353) because the transaction from the minter tries to reuse the already spent output [`8942e5ef0d4ace158a4fddd5153d320701bd13370ff8fecef13795cdd8ff1dc5:1`](https://mempool.space/tx/8942e5ef0d4ace158a4fddd5153d320701bd13370ff8fecef13795cdd8ff1dc5#vout=1).

This proposal should address these issues by:
* Removing the duplicate outpoints from the minter's state.
* Discarding any transaction sent by the minter to the Bitcoin network that uses one of the duplicate outpoints. This is safe to do because those transactions are invalid and will never be accepted by the Bitcoin network.

The expected result is that the aforementioned withdrawals are considered as pending by the minter, as if they were going to be processed by the minter for the first time.

## Release Notes

```
git log --format='%C(auto) %h %s' 307d063f3473cf5261ce84ccafaecceb8440e4e8..00b276124eacd236b379f09322064c602fcfe9e2 -- rs/bitcoin/ckbtc/minter
00b276124e fix(ckbtc): unstuck ckbtc withdrawal requests (#9450)
2b46af588f revert(ckbtc): keeping finalized UTXOs in state (#9505)
b4741211f2 test(ckbtc): Update ckBTC minter events for replay tests (#9497)
9a4fa5e220 fix(ckbtc): Clear get_utxos_cache when tip height changes (#9475)
a08eb494fe chore(de-fi): Add separator before type suffix in integer literals. (#9433)
a639c6bab4 test(ckbtc): Update ckBTC minter events for replay tests (#9441)
dd06753d23 fix(ckbtc): keeping finalized UTXOs in state (#9437)
cca3eb1c44 refactor: Group cycles related types in new ic-types-cycles crate (#9341)
b34d5ed28c chore: Upgrade rustc to 1.93.1  (#9113)
713c399a69 fix: deflake //rs/bitcoin/ckbtc/minter:ckbtc_minter_canbench_test (#9220)
042becb616 fix(ckbtc/ckdoge): destructure init args (#9108)
```

## Upgrade args

```
git fetch
git checkout 00b276124eacd236b379f09322064c602fcfe9e2
didc encode -d rs/bitcoin/ckbtc/minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped Wasm matches the proposed hash.

```
git fetch
git checkout 00b276124eacd236b379f09322064c602fcfe9e2
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
