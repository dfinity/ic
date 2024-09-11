# Proposal to upgrade the ckETH minter canister

Git hash: `dfb1c634d08ec2248feb4d5792554bbe43e068c7`

New compressed Wasm hash: `1a19eb2e54d5a7369ed13c6bdfe795429c8a476aac9e8d8e0cda3bee3d861271`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/132132

---

## Motivation
The Ethereum JSON-RPC provider Ankr (`rpc.ankr.com`) recently dropped its IPv6 connectivity and will need according to its support team a month to fix it.
This resulted in the ckETH minter being stuck and unable to process deposits nor withdrawals.
As an emergency fix, this proposal replaces Ankr by another provider: `eth-pokt.nodies.app` from [Pocket Network](https://www.pokt.network/).
The long term solution is to use a more robust strategy (e.g., agreement among 3 providers, when 4 were queried) using the EVM-RPC canister.


## Upgrade args

```
git fetch
git checkout dfb1c634d08ec2248feb4d5792554bbe43e068c7
cd rs/ethereum/cketh/minter
didc encode '()'
```

## Release Notes

```
git log --format='%C(auto) %h %s' 667a6bd3bc08c58535b8b63bfebc01dba89c0704..dfb1c634d08ec2248feb4d5792554bbe43e068c7 -- rs/ethereum/cketh/minter
888341976 fix(cketh): Replace provider Ankr (#1412)
4928a6562 fix(cketh): Retry HTTPs outcalls (#1387)
4d09678d2 chore: sort rust derive traits (#1241)
83af06c5c fix(cketh): Trim logs to 2 MB (#1210)
d4c3bb26c chore: upgrade crates and use workspace version (#1207)
c6e64a7e3 chore(crypto): CRP-2567 Rename ic_crypto_ecdsa_secp256k1 crate (#999)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout dfb1c634d08ec2248feb4d5792554bbe43e068c7
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
