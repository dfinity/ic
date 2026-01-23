# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `b2d93fe83a8f878a331d73df1cffed72022860b2`

New compressed Wasm hash: `f3c1c42fa76e4fc57a54b915418803238b6da2cdb772dd63e9e2c0dc80fd56f3`

Upgrade args hash: `d84bd4703a47528b09efe3e5dedc6e6e4e3a56ae156099ffcde563055d42b414`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/139767

---

## Motivation

Besides upgrading the ckBTC minter to the latest version,
the main motivation for this proposal is to reduce the number of confirmations required by the minter to process a deposit and mint ckBTC.
Changing that number from 6 to 4 should only marginally impact the security of the ckBTC token while improving the user experience for certain applications (e.g., being able to react to falling market prices more quickly for lending applications).

## Release Notes

```
git log --format='%C(auto) %h %s' 61d605fd75c61072bfeed9a61adf7eca2b8dca5f..b2d93fe83a8f878a331d73df1cffed72022860b2 -- rs/bitcoin/ckbtc/minter
5031b9fe5a fix(ckdoge): reject deposits below minimum amount (#8428)
3314a4b8dd feat(ckdoge): ckDOGE minter dashboard (#8341)
5490d8bb30 fix(ckbtc/ckdoge): ensure that the fee rate of replacement transactions increases (#8345)
8bbd825e1f feat(ckBTC_Minter): DEFI-2246: Add decode_ledger_memo query endpoint to ckBTC minter (#7862)
cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
e0e6f70b6c fix(ckdoge): use legacy P2PKH transactions for withdrawals (#8187)
bb5c405c6f feat(ckbtc): Use 25th percentile fee for UTXO consolidation (#8150)
c711180b49 feat(ckbtc): remove the force_resubmit flag (#8069)
c9da22f4be refactor(ckbtc): deprecate no longer produced minter events (#8080)
68ae575316 refactor(ckdoge): Dedicated events (#8035)
23265b3882 refactor(ckbtc): Generic events (#7991)
 ```

## Upgrade args

* Change the number of confirmations required by the minter to process a deposit and mint ckBTC to 4.
* Ensure that the deposit amount is at least 300 sats, which corresponds to the dust limit of the Bitcoin network for the type of addresses used for deposits (P2WPKH).

```
git fetch
git checkout b2d93fe83a8f878a331d73df1cffed72022860b2
didc encode -d rs/bitcoin/ckbtc/minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = opt record { deposit_btc_min_amount = opt (300 : nat64); min_confirmations = opt (4 : nat32); } })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout b2d93fe83a8f878a331d73df1cffed72022860b2
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
