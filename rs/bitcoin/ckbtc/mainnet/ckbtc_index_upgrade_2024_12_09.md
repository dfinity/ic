# Proposal to upgrade the ckBTC index canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2190613d3b5bcd9b74c382b22d151580b8ac271a`

New compressed Wasm hash: `2adc74fe5667f26ea4c4006309d99b1dfa71787aa43a5c168cb08ec725677996`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/133823

---

## Motivation

Upgrade the ckBTC index canister to the same version ([ledger-suite-icrc-2024-11-28](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2024-11-28)) as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.

## Upgrade args

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
cd rs/ledger_suite/icrc1/index-ng
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ledger_suite/icrc1/index-ng
2b21236228 refactor(ICP_ledger): FI-1570: Rename ledger suite memory-related metrics (#2545)
ee1006503b test(ICRC_index_ng): FI-1519: Add test for ICRC index-ng sync with ledger with various intervals (#2313)
15d752c5dd chore: avoid reexports from StateMachine tests (#2370)
d361dd6923 feat: Update cycles cost for compute (#2308)
07cf5773d4 feat(Index-ng): FI-1389: Disallow upgrading ICRC index-ng from u64 to u256 or vice versa (#1987)
03dd6ee6de fix(Ledger-Suite): renamed state machine tests (#2014)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
