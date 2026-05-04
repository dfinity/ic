# Proposal to upgrade the ckETH minter canister

Git hash: `3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d`

New compressed Wasm hash: `658afe755a0cdc75bc0997d793dd9522332ad182aaa7c69d696d6b0e2e6902bf`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/130341

---

## Motivation

Upgrade the ckETH minter to the latest version for the following main reasons:
* Fix a bug affecting ckERC20 withdrawals which were unnecessarily delayed as soon as the estimated transaction fees increased.
* Expand the existing method `eip_1559_transaction_price` to also return the estimated transaction price of a ckERC20 withdrawal.

Note that the other changes related to using the EVM-RPC canister are gated behind a feature flag (`State::evm_rpc_id`) and are currently not enabled.

## Upgrade args

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {}})'
```

## Release Notes

```
git log --format="%C(auto) %h %s" 7fbb84aad7188d1d5b3e17b170997c29d1598cb8..3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d -- rs/ethereum/cketh/minter
b4be567dc chore: Bump rust version to 1.80 (#642)
0838df154 feat(ckerc20): Use EVM-RPC canister to call `eth_feeHistory` (#508)
1add852d7 feat(ckerc20): Use EVM-RPC canister to call `eth_getLogs` (#400)
ce468ecac feat(ckerc20): Simplify adding new ckERC20 token (II) (#365)
ff90a5234 feat(ckerc20): Simplify adding new ckERC20 token
f420b4d6e fix(ckerc20): Stuck ckERC20 withdrawal when fee increases
576bb8d17 chore: add buildifier sort comment to Bazel files
7c6d7f37e chore(IDX): align cargo & bazel deps
baa8b3788 fix(IDX): remove unnecessary cketh minter deps
1978a079c feat(ckerc20): Use EVM-RPC canister to call `eth_getBlockByNumber`
57b9b8aa6 chore(ckerc20): Remove SkippedEvent from internal state XC-127
7b084ccce Merge branch 'paulliu/erc20-transaction-price' into 'master'
7227485c6 feat(ckerc20): add erc20 support to eip_1559_transaction_price XC-114
421c2230b Merge branch 'gdemay/XC-130-feature-gate-evm-rpc' into 'master'
5b670e409 feat(ckerc20): Feature gate to use the EVM-RPC canister
8848f8ea5 chore: upgrade flate2, rayon, threadpool, regex
695a0affa chore: Bump rust version to 1.78
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3d0b3f10417fc6708e8b5d844a0bac5e86f3e17d
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
