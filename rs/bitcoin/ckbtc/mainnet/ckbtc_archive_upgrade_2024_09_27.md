# Proposal to upgrade the ckBTC archive canister

Git hash: `d4ee25b0865e89d3eaac13a60f0016d5e3296b31`

New compressed Wasm hash: `9476aa71bcee621aba93a3d7c115c543f42c543de840da3224c5f70a32dbfe4d`

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/132127

---

## Motivation

Upgrade the ckBTC archive canister to the same version as the ckBTC ledger canister to maintain a consistent versioning across the ckBTC ledger suite.

## Upgrade args

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
cd rs/rosetta-api/icrc1/archive
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..d4ee25b0865e89d3eaac13a60f0016d5e3296b31 -- rs/rosetta-api/icrc1/archive
4d09678d2 chore: sort rust derive traits (#1241)
d71e09e83 chore: add decoding quota to http_request in SNS and ICRC1 canisters (#1101)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d4ee25b0865e89d3eaac13a60f0016d5e3296b31
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-archive.wasm.gz
```
