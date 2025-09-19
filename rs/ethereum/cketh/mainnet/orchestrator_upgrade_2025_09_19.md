# Proposal to upgrade the ledger suite orchestrator canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `3f3d9bfac750f82f424185ac5b32a756cfd45ad9`

New compressed Wasm hash: `65922cb648428a74535c5aa58a36adacb508f6aa0609298030395d39b84e8453`

Upgrade args hash: `bb60ab96aacd95356d66cbb608ec81622efc29a65d84ad7e32b3e3fa603c8f99`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/137335

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Release Notes

```
git log --format='%C(auto) %h %s' 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ethereum/ledger-suite-orchestrator
49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
55ec0283bb build: update ic0 to v1.0.0. (#6216)
a4c1c9bce1 chore: update rust to 1.88.0 (#6045)
 ```

## Upgrade args

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
didc encode -d rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { UpgradeArg = record {git_commit_hash = opt "3f3d9bfac750f82f424185ac5b32a756cfd45ad9"; ledger_compressed_wasm_hash = opt "d602c900543073178bddea5bda3f89dd5cfc3dfecda88ed241424955656e7043"; index_compressed_wasm_hash = opt "b39d419cdd290515cf4c16a6878c8bb1a25697ee4d4678c895475e3322ed7d64"; archive_compressed_wasm_hash = opt "80416919154866c86bd1eb5f480fda36ca7354bff29c1760847098bf01d22d03"}})' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```