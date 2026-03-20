# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c016162d2861e5ad6260d4f62c511a3e5cef5a31`

New compressed Wasm hash: `96e98bbddf63f1b381f1a36801f3e9d93336b0023823b4d33d38fead41103fa1`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/140090

---

## Motivation

Due to the security incident explained in this [forum post](https://forum.dfinity.org/t/proposal-140929-to-upgrade-the-ckbtc-minter/65401/3), the following ckBTC withdrawals (ckBTC -> BTC) are currently stuck:

* [3459007](https://dashboard.internetcomputer.org/bitcoin/transaction/3459007), [3459009](https://dashboard.internetcomputer.org/bitcoin/transaction/3459009), and [3459013](https://dashboard.internetcomputer.org/bitcoin/transaction/3459013) because the transaction from the minter tries to reuse the already spent output [`91bb46443799335076fbcd117f2295c7499d02dd3a59c22a531d31591114b303:5`](https://mempool.space/tx/91bb46443799335076fbcd117f2295c7499d02dd3a59c22a531d31591114b303#vout=5).
* [3489347](https://dashboard.internetcomputer.org/bitcoin/transaction/3489347) and [3489353](https://dashboard.internetcomputer.org/bitcoin/transaction/3489353) because the transaction from the minter tries to reuse the already spent output [`8942e5ef0d4ace158a4fddd5153d320701bd13370ff8fecef13795cdd8ff1dc5:1`](https://mempool.space/tx/8942e5ef0d4ace158a4fddd5153d320701bd13370ff8fecef13795cdd8ff1dc5#vout=1).

This proposal should address these issues by:
* Removing the duplicated outpoints from the minter's state.
* Discarding any transaction sent by the minter to the Bitcoin network that uses one of the duplicated outpoints. This is safe to do because those transactions are invalid and will never be accepted by the Bitcoin network.

The expected result is that the aforementioned withdrawals are considered as pending by the minter, like they would be processed by the minter for the first time.

## Release Notes

```
git log --format='%C(auto) %h %s' b2d93fe83a8f878a331d73df1cffed72022860b2..c016162d2861e5ad6260d4f62c511a3e5cef5a31 -- rs/bitcoin/ckbtc/minter
79cbc4b37c fix(ckbtc): compute minter str address in retrieve_btc (#8671)
990e96bf57 fix(ckbtc/ckdoge): defuse guard directly after signing transaction (#8579)
 ```

## Upgrade args

```
git fetch
git checkout c016162d2861e5ad6260d4f62c511a3e5cef5a31
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c016162d2861e5ad6260d4f62c511a3e5cef5a31
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
