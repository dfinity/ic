# Proposal to upgrade the ckETH archive canister

Git hash: `3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d`

New compressed Wasm hash: `5bd1f69540bd48493018e13bb5ad25aba75d59403ced1d5958bf718147228d31`

Target canister: `xob7s-iqaaa-aaaar-qacra-cai`

Previous ckETH archive proposal: None (was spawned off by the ckETH ledger with git hash `5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576`)

---

## Motivation
Upgrade the ckETH archive canister to the latest version to add support for the [ICRC-21: Canister Call Consent Messages](https://github.com/dfinity/wg-identity-authentication/blob/fd846030109710cab67d9381485a73db424f2b07/topics/ICRC-21/icrc_21_consent_msg.md) standard.


## Upgrade args

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
cd rs/rosetta-api/icrc1/archive
didc encode '()'
```

## Release Notes

```
git log --format="%C(auto) %h %s" 5ecbd59c6c9f9f874d4340f9fbbd96af07aa2576..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/rosetta-api/icrc1/archive
576bb8d17 chore: add buildifier sort comment to Bazel files
f7fe40b7d Merge branch 'mathias-FI-1310-add-heap-memory-usage-metric' into 'master'
0c16902ca feat(ledger_suite): FI-1310: Add total memory usage metrics for ledger, archive, and index canisters
a5c8d79ad feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
1bfe616ec feat: build Rust canisters with opt-level=3 by default
96d973666 chore(rosetta): FI-1253: Sort dependencies in BUILD.bazel and Cargo.toml files under rs/rosetta-api
75b477a1e fix: ICRC Archive icrc3_get_block should return at most 100 blocks
d39f28fbd feat(icrc-archive): support ICRC-3 in the ICRC Archive
bc81e20f9 chore: upgrade `ic-stable-structures`
a8f0d7f61 build: upgrade candid to 0.10
a163262f1 chore(release): Bump up the bazel versions for all crates as well
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-archive-u256.wasm.gz
```