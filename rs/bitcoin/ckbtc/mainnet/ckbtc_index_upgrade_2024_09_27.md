# Proposal to upgrade the ckBTC index canister

Git hash: `d4ee25b0865e89d3eaac13a60f0016d5e3296b31`

New compressed Wasm hash: `612410c71e893bb64772ab8131d77264740398f3932d873cb4f640fc257f9e61`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/132167

---

## Motivation

Upgrade the ckBTC index canister to the same version as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.

## Upgrade args

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
cd rs/rosetta-api/icrc1/index-ng
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/rosetta-api/icrc1/index-ng
4d09678d2 chore: sort rust derive traits (#1241)
d4c3bb26c chore: upgrade crates and use workspace version (#1207)
d71e09e83 chore: add decoding quota to http_request in SNS and ICRC1 canisters (#1101)
1fd18580d chore(ICP-Ledger): FI-1426: remove maximum number of accounts (#972)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
