# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `552cd582607508df70533f21e3c0bfce19f8e46b`

New compressed Wasm hash: `8da4947f698ef5f034e41b1879bc8f51dc9dc9442a8dabe36df000d5d094e0ef`

Upgrade args hash: `445734292959382834da46c68370d87f8117d50271f6b8a97d5eb8dadac8cb94`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/134970

---

## Motivation

Update the ckBTC minter to include the latest code changes, notably:

* Remove empty ReceivedUtxos events from event log
* Upgrade bitcoin crate
* Place `update_balance` and `retrieve_btc` guards on user ledger accounts to improve concurrency

## Upgrade args

```
git fetch
git checkout 552cd582607508df70533f21e3c0bfce19f8e46b
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 744f4683df2ca79f5f537b3db48a1c03d4ff084e..552cd582607508df70533f21e3c0bfce19f8e46b -- rs/bitcoin/ckbtc/minter
552cd58260 feat(ckbtc): Place update_balance and retrieve_btc guards on user accounts (#3811)
97bcf0945c chore(crypto): CRP-2693 Move ic-crypto-secp256k1 to packages (#3784)
0c343040da chore(ckbtc): Separate event types for mainnet and testnet logs (#3720)
967fe21189 chore: bitcoin crate upgrade (#3080)
f52dbf1b84 chore(ckbtc): Remove empty ReceivedUtxos events from event log (#3434)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 552cd582607508df70533f21e3c0bfce19f8e46b
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
