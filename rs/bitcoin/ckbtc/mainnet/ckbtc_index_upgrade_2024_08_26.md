# Proposal to upgrade the ckBTC index canister

Git hash: `3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d`

New compressed Wasm hash: `08ae5042c8e413716d04a08db886b8c6b01bb610b8197cdbe052c59538b924f0`

Target canister: `n5wcd-faaaa-aaaar-qaaea-cai`

Previous ckBTC index proposal: https://dashboard.internetcomputer.org/proposal/132128

---

## Motivation
The previous proposal [132128](https://dashboard.internetcomputer.org/proposal/132128) was executed, but the upgrade failed during the `post_upgrade` and the state of the canister was reverted.
This can be seen by verifying that the currently deployed wasm module (e.g. with `dfx canister --ic info n5wcd-faaaa-aaaar-qaaea-cai`) is still `0x340eb880fb50cb7f437d284f2dc70d796cc86859cb990e39f1c4981e2b52dab5`, which corresponds to the version from the last successfully executed proposal [125590](https://dashboard.internetcomputer.org/proposal/125590).
The reason for the failure was that the wrong wasm was used (`ic-icrc1-index.wasm.gz` instead of `ic-icrc1-index-ng.wasm.gz`).

Similarly to [132128](https://dashboard.internetcomputer.org/proposal/132128), this proposal is meant to upgrade the ckBTC index canister to the latest version to add support for the [ICRC-21: Canister Call Consent Messages](https://github.com/dfinity/wg-identity-authentication/blob/fd846030109710cab67d9381485a73db424f2b07/topics/ICRC-21/icrc_21_consent_msg.md) standard.


## Upgrade args

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
cd rs/rosetta-api/icrc1/index-ng
didc encode '()'
```

## Release Notes

```
git log --format=%C(auto) %h %s 24fd80082f40de6d0b3cd7876be09ef1aadbde86..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/rosetta-api/icrc1/index-ng
b4be567dc chore: Bump rust version to 1.80 (#642)
eec6107fa chore: remove obsolete cost scaling feature flag (#502)
18243444a fix(ICRC-Index): FI-1382: remove comment on removing 0 balance accounts (#341)
576bb8d17 chore: add buildifier sort comment to Bazel files
f7fe40b7d Merge branch 'mathias-FI-1310-add-heap-memory-usage-metric' into 'master'
0c16902ca feat(ledger_suite): FI-1310: Add total memory usage metrics for ledger, archive, and index canisters
a5c8d79ad feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
610ebf1b7 chore(ICRC1 index-ng): FI-1306: Extract index-ng tests into separate file and shorten runtimes
d557530ae chore(index-ng): FI-1296: Set index-ng integration test timeout to long
e73f59f99 feat(icrc1-index-ng): FI-1296: Make index-ng interval for retrieving blocks from the ledger configurable
1bfe616ec feat: build Rust canisters with opt-level=3 by default
96d973666 chore(rosetta): FI-1253: Sort dependencies in BUILD.bazel and Cargo.toml files under rs/rosetta-api
6c404992f chore: enable DTS in all StateMachine tests by default
e9475596c Merge branch 'FI-1194' into 'master'
97282de22 feat(icrc-index-ng): support ICRC-3
00e10d345 feat(ledger): Enable ICRC1 ledger to change archive options upon upgrades
be2ab73ba chore(icrc-index-ng): test against ledger wo ICRC-3
0fe5aff1e chore: Move num-traits dependency to workspace
e1c1033c7 feat(sns): Enable upgrading the SNS Ledger suite to the latest canister versions
b669077b2 feat(icrc): Add more controllers to archive spawned by ledger
bc81e20f9 chore: upgrade `ic-stable-structures`
2c30c7ac8 feat(FI-1114): [ICRC Rosetta] Property based testing
fbcfbd5e3 feat(ckerc20): PoC for a ledger suite orchestrator canister
a8f0d7f61 build: upgrade candid to 0.10
b835f6ebb chore: bump Rust version to 1.75
6e9c3da68 fix(index-ng): Simplify the timer structure
dced7733d feat(FI-1074) [ICRC-1 Rosetta] converted principal based valid blockchain strategy to basicidentity
c603a7f14 feat(icrc_index_ng): read ledger_id from old index state in post_upgrade
5ae303770 chore: bump rust to 1.73
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-index-ng.wasm.gz
```
