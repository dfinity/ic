# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `157c4f6fdfa55b40ebde0fe8aad9aa39ca0dae4a`

New compressed Wasm hash: `fd77fa60cd0cae8d942afd25f77a1778d05357afd297f97859a460a135728ccc`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/133058

---

## Motivation

This proposal upgrades the ckETH minter to change how Ethereum is reached:
* To use the [EVM RPC canister](https://dashboard.internetcomputer.org/canister/7hfb6-caaaa-aaaar-qadga-cai) to reach Ethereum. This allows to use a wider variety of Ethereum JSON-RPC providers since most of them require using API keys, which is supported by the [EVM RPC canister](https://dashboard.internetcomputer.org/canister/7hfb6-caaaa-aaaar-qadga-cai).
* To use a 3-out-of-4 consensus strategy to aggregate answers from multiple providers. This is a more robust strategy than the current one, which requires equality between 3 providers (3-out-of-3).


## Upgrade args

```
git fetch
git checkout 157c4f6fdfa55b40ebde0fe8aad9aa39ca0dae4a
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {evm_rpc_id = opt principal "7hfb6-caaaa-aaaar-qadga-cai"}})' | xxd -r -p | sha256sum
```

* The principal `7hfb6-caaaa-aaaar-qadga-cai` is the canister ID of the [EVM RPC canister](https://dashboard.internetcomputer.org/canister/7hfb6-caaaa-aaaar-qadga-cai).

## Release Notes

```
git log --format='%C(auto) %h %s' 511ad1cf505003e33baf0ce0eefa0168aad91bf1..157c4f6fdfa55b40ebde0fe8aad9aa39ca0dae4a -- rs/ethereum/cketh/minter
c8c0f2127 feat(cketh): add EVM RPC canister ID to the minter info endpoint (#2127)
75037720e chore(IDX): disable closure tests (#2103)
e79f39857 feat(cketh): Providers chosen by the EVM RPC canister (#2023)
45eee81e4 feat(cketh): threshold consensus strategy for HTTPs outcalls (#1997)
05d54e257 feat(cketh): Use  EVM-RPC canister 2.0.0 (#1831)
fcbc91f0a chore: update `ic-cdk` to 0.16.0 (#1868)
eada4b26a chore(ic): Update python formatting rules for the monorepo (#1751)
3bbabefb7 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
2f71ed9e8 chore(cketh): Publish `ic-ethereum-types` (#1723)
d70fb272a chore: use `ic-sha3` (#1718)
32de73bf9 chore(crypto): Publish `ic-sha3` (#1674)
46cd07354 fix(IDX): set compatibility on targets (#1658)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 157c4f6fdfa55b40ebde0fe8aad9aa39ca0dae4a
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
