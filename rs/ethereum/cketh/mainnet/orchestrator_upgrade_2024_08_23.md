# Proposal to upgrade the ledger suite orchestrator canister

Git hash: `667a6bd3bc08c58535b8b63bfebc01dba89c0704`

New compressed Wasm hash: `fedd6d09b477eb6f79a682fc1868c97de04fe4469817374a8ddf8964f47485b2`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/132130

---

## Motivation
Update the ckERC20 ledger suite orchestrator canister to include the latest code changes:
* Update `ic-cdk` dependency to patch a security issue.

## Upgrade args

```
git fetch
git checkout 667a6bd3bc08c58535b8b63bfebc01dba89c0704
cd rs/ethereum/ledger-suite-orchestrator
didc encode '()'
```

## Release Notes

```
git log --format=%C(auto) %h %s 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..667a6bd3bc08c58535b8b63bfebc01dba89c0704 -- rs/ethereum/ledger-suite-orchestrator
667a6bd3b feat: add a metric to track the total memory usage of XC-canisters (#1050)
ca24b5d66 chore: sort dependencies in Cargo.toml files (#828)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 667a6bd3bc08c58535b8b63bfebc01dba89c0704
./cild-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
