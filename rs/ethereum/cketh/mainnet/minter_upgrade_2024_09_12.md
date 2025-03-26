# Proposal to upgrade the ckETH minter canister

Git hash: `603473e2a9d4f5a0259bc4ea6aee4ba438186fba`

New compressed Wasm hash: `216c35ce5d0a93bbe40d77e3f80362ef15a317275be0d139f5d733f22e2665c3`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/132415

---

## Motivation

The ckETH minter is currently unable to process conversions between ETH/ERC20 and ckETH/ckERC20 due to the following events:
1. Proposal [132415](https://dashboard.internetcomputer.org/proposal/132415) was executed at 2024.09.11 09:28 (UTC) and successfully replaced the Ethereum JSON-RPC provider Ankr (rpc.ankr.com) with `eth-pokt.nodies.app` from [Pocket Network](https://www.pokt.network/).
2. Unfortunately, at the same time the Ethereum JSON-RPC provider LlamaNodes  `eth.llamarpc.com` was down and constantly replying with `no response`. This seems to have been resolved since the ckETH minter did make progress around 2024.09.11 22:00 (UTC) but stopped since then.
3. The [logs](https://sv3dd-oaaaa-aaaar-qacoa-cai.raw.icp0.io/logs?sort=desc) show that responses from the Ethereum JSON-RPC provider Pocket Network (`eth-pokt.nodies.app`) differ between the replicas resulting in consensus failures.

As a temporary fix, this proposal replaces the Ethereum JSON-RPC provider Pocket Network (`eth-pokt.nodies.app`) with the Ethereum JSON-RPC provider BlockPi (`https://ethereum.blockpi.network/v1/rpc/public).

## Upgrade args

```
git fetch
git checkout 603473e2a9d4f5a0259bc4ea6aee4ba438186fba
cd rs/ethereum/cketh/minter
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' dfb1c634d08ec2248feb4d5792554bbe43e068c7..603473e2a9d4f5a0259bc4ea6aee4ba438186fba -- rs/ethereum/cketh/minter
603473e2a fix(cketh): Replace provider POKT Network (#1461)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 603473e2a9d4f5a0259bc4ea6aee4ba438186fba
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
