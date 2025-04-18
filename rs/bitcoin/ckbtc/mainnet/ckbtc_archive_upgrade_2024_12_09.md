# Proposal to upgrade the ckBTC archive canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2190613d3b5bcd9b74c382b22d151580b8ac271a`

New compressed Wasm hash: `f94cf1db965b7042197e5894fef54f5f413bb2ebc607ff0fb59c9d4dfd3babea`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/133825

---

## Motivation
Upgrade the ckBTC archive canister to the same version ([ledger-suite-icrc-2024-11-28](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2024-11-28)) as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.


## Upgrade args

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
cd rs/ledger_suite/icrc1/archive
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' e54d3fa34ded227c885d04e64505fa4b5d564743..2190613d3b5bcd9b74c382b22d151580b8ac271a -- rs/ledger_suite/icrc1/archive
2b21236228 refactor(ICP_ledger): FI-1570: Rename ledger suite memory-related metrics (#2545)
15d752c5dd chore: avoid reexports from StateMachine tests (#2370)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2190613d3b5bcd9b74c382b22d151580b8ac271a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
