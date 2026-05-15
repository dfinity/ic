
# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `50ba5020d6d654d70a48d964969fef8443fb42ae`

New compressed Wasm hash: `789d9e138796c30bb63bc6482918d529f24627c0b96ecb81196a642a5dd236bc`

Upgrade args hash: `abf6b9f54bb94025c0aff10c4eb05e182118052d6c7a490c2aa50ea651ed7d23`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/141330

---

## Motivation

* Support [ICRC-21](https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md) consent messages.

## Release Notes

```
git log --format='%C(auto) %h %s' ebb18a0983f28f1882b9957e99f072695f43141e..50ba5020d6d654d70a48d964969fef8443fb42ae -- rs/bitcoin/ckbtc/minter
ce5f73fa73 feat(ckbtc-minter): support ICRC-21 consent messages (#10093)
88a0df635a chore(icrc-ledger-types): DEFI-1894: Switch icrc-ledger-types bazel variants (#9900)
d3b3351fa3 feat(icrc1): implement ICRC-122/152 with ledger endpoints, index-ng, and Rosetta support (#9586)
56195980e1 fix: deflake //rs/bitcoin/ckbtc/minter:ckbtc_minter_tests (#9801)
 ```

## Upgrade args

```
git fetch
git checkout 50ba5020d6d654d70a48d964969fef8443fb42ae
didc encode -d rs/bitcoin/ckbtc/minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 50ba5020d6d654d70a48d964969fef8443fb42ae
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
