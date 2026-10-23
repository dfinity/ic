# Proposal to upgrade the ckDOGE minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `50ba5020d6d654d70a48d964969fef8443fb42ae`

New compressed Wasm hash: `02b4382005cdfd8503cee45af22d94e00c3b07ef183d2012b876bbec97f8b020`

Upgrade args hash: `2fe5c6f806dbe3b1d986577ea120c775b8b1fc5dfaafa1d6db889ecff6bc8a32`

Target canister: `eqltq-xqaaa-aaaar-qb3vq-cai`

Previous ckDOGE minter proposal: https://dashboard.internetcomputer.org/proposal/140930

---

## Motivation

* Support [ICRC-21](https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md) consent messages.


## Release Notes

```
git log --format='%C(auto) %h %s' 78c8977a7a6c496435edfcce47ceecded9779b21..50ba5020d6d654d70a48d964969fef8443fb42ae -- rs/bitcoin/ckbtc rs/dogecoin/ckdoge
bb3d2afabe feat(ckdoge-minter): support ICRC-21 consent messages (#10140)
ce5f73fa73 feat(ckbtc-minter): support ICRC-21 consent messages (#10093)
936346afd2 test(ckdoge): fix ckdoge test setup (#10082)
88a0df635a chore(icrc-ledger-types): DEFI-1894: Switch icrc-ledger-types bazel variants (#9900)
d3b3351fa3 feat(icrc1): implement ICRC-122/152 with ledger endpoints, index-ng, and Rosetta support (#9586)
6ec8857cd3 chore(ckbtc): proposal to upgade ckBTC minter canister (#9802)
56195980e1 fix: deflake //rs/bitcoin/ckbtc/minter:ckbtc_minter_tests (#9801)
a22189c20d fix(ckbtc): prevent double-mint of cached UTXOs after transaction finalization (#9596)
31d726d72d chore(ckbtc): upgrade ckBTC minter to unstuck transactions (#9525)
675a14c1af test(defi): move event files to CDN (#9563)
b608c374f2 chore: 42u64 -> 42_u64 (#9523)
00b276124e fix(ckbtc): unstuck ckbtc withdrawal requests (#9450)
2b46af588f revert(ckbtc): keeping finalized UTXOs in state (#9505)
b4741211f2 test(ckbtc): Update ckBTC minter events for replay tests (#9497)
7a6e6aa45c test(ckdoge): add replay events test for ckDOGE minter (#9488)
81206c3656 chore(ckbtc): proposal to upgrade ckbtc minter (#9469)
f7c5ad81f1 chore(ckdoge): Proposal to upgrade the ckDOGE minter (#9471)
9a4fa5e220 fix(ckbtc): Clear get_utxos_cache when tip height changes (#9475)
a08eb494fe chore(de-fi): Add separator before type suffix in integer literals. (#9433)
a639c6bab4 test(ckbtc): Update ckBTC minter events for replay tests (#9441)
dd06753d23 fix(ckbtc): keeping finalized UTXOs in state (#9437)
cca3eb1c44 refactor: Group cycles related types in new ic-types-cycles crate (#9341)
b8af031139 chore(Ledgers): DEFI-2694: Upgrade ledger suite to ledger-suite-icrc-2026-03-09 (#9321)
b34d5ed28c chore: Upgrade rustc to 1.93.1  (#9113)
713c399a69 fix: deflake //rs/bitcoin/ckbtc/minter:ckbtc_minter_canbench_test (#9220)
13d0443d01 fix: deflake //rs/dogecoin/ckdoge/minter:integration_tests (#9163)
042becb616 fix(ckbtc/ckdoge): destructure init args (#9108)
82974651ee fix(ckdoge): fix flaky ckbtc/ckdoge minter integration tests (#9075)
39f863e568 test(ckdoge): lower num utxos in `should_cancel_and_reimburse_large_withdrawal` test (#9011)
c2fa5df535 chore(ckbtc): DEFI-2652: Upgrade ledger suite to 2026-02-02 (#8948)
c1ad68eb83 chore(ckdoge): DEFI-2652: Upgrade ledger suite to 2026-02-02 (#8966)
cc8d991db7 chore(ckbtc): proposal to upgrade the ckBTC minter (#8960)
c18c2a6d59 chore: proposal to upgrade the ckDOGE minter canister (2026-02-09) (#8739)
 ```

## Upgrade args

```
git fetch
git checkout 50ba5020d6d654d70a48d964969fef8443fb42ae
didc encode -d rs/dogecoin/ckdoge/minter/ckdoge_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 50ba5020d6d654d70a48d964969fef8443fb42ae
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckdoge-minter.wasm.gz
```
