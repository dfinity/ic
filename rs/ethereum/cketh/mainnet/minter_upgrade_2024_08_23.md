# Proposal to upgrade the ckETH minter canister

Git hash: `667a6bd3bc08c58535b8b63bfebc01dba89c0704`

New compressed Wasm hash: `d6c0cf6adb923b70dd869b5b75b41e6b8db3ff2e0bb50a5e572353a94fade334`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/131485

---

## Motivation
Update the ckETH minter canister to include the latest code changes:
* Update `ic-cdk` dependency to patch a security issue.

Note that the other changes related to using the EVM-RPC canister are gated behind a feature flag (`State::evm_rpc_id`) and are currently not enabled.

## Upgrade args

```
git fetch
git checkout 667a6bd3bc08c58535b8b63bfebc01dba89c0704
cd rs/ethereum/cketh/minter
didc encode '()'
```

## Release Notes

```
git log --format=%C(auto) %h %s 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d..667a6bd3bc08c58535b8b63bfebc01dba89c0704 -- rs/ethereum/cketh/minter
667a6bd3b feat: add a metric to track the total memory usage of XC-canisters (#1050)
24d732eb1 refactor(ckerc20): Simplify return type of `eth_rpc::call`  (#853)
0cb4c3719 feat(ckerc20): Use EVM-RPC canister to call `eth_sendRawTransaction` (#836)
ca24b5d66 chore: sort dependencies in Cargo.toml files (#828)
92f7c043a chore(ckerc20): NNS proposal to upgrade the ckETH minter (#748)
172f24d0b feat(ckerc20): Use EVM-RPC canister to call `eth_getTransactionCount` (#792)
0e9193dd8 feat(ckerc20): Use EVM-RPC canister to call `eth_getTransactionReceipt` (#738)
527338a68 test(ckerc20): Ensure same processing between EVM-RPC and minter results (#562)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 667a6bd3bc08c58535b8b63bfebc01dba89c0704
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
