# Proposal to upgrade the ckETH minter canister

Git hash: `f6d3e13cf080335c7ed7d5f9144f538241fa4122`

New compressed Wasm hash: `66b442e46affef8c991fc11b7e9dccd481f2ec65b29d9c4a9f2867b918ff5e3e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/126314

---

## Motivation
Improve the minter interface to provide more information to users and front-end developers:
* Added a new query endpoint `get_minter_info`, to retrieve parameters used by the minter.
* Change the endpoint `eip_1559_transaction_price` to be a query endpoint. This now returns the last transaction price estimate with a new optional timestamp of when this estimate was made.
* Change the developer dashboard to use monospace fonts for better readability.


## Upgrade args

```
git fetch
git checkout f6d3e13cf080335c7ed7d5f9144f538241fa4122
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {} })'
```

## Release Notes

```
git log --format="%C(auto) %h %s" 51d01d3936498d4010de54505d6433e9ad5cc62b..f6d3e13cf080335c7ed7d5f9144f538241fa4122 -- rs/ethereum/cketh/minter
 e1bd8d1e67 test(cketh): Extract test infrastructure to a new crate `ic-cketh-test-utils`
 256654b959 feat(cketh): add `minter_info` endpoint to the ckETH minter
 25591aee7c feat(cketh): Add fee to metrics
 7881d9cc6b feat(cketh): query endpoint to retrieve last transaction price estimate [override-didc-check]
 f3d614b6e3 chore: rename ic00_types to management_canister_types
 221142844a Merge branch 'gdemay/XC-51-update-stable-memory' into 'master'
 bc81e20f92 chore: upgrade `ic-stable-structures`
 0b7d17ebbf feat(ckerc20): Helper Contract
 db66af382e docs(cketh): consolidate ckETH docs and docs for ckERC20
 d0aba97760 refactor(ckerc20): new crate `ic-ethereum-types` for common Ethereum types
 879331e824 build: fix existing cargo clippy errors and make sure we run cargo clippy on the whole repository only with relevant lints
 fa6adacec4 Merge branch 'mk/bazel_ic_test2' into 'master'
 40db11f8e0 Chore: Move sandbox env declarations to a common place
 a8f0d7f61b build: upgrade candid to 0.10
 1538e8610b docs(cketh): fix incorrect command in README
 57580e5ebc chore(ckETH): makes the ckETH dashboard use monospace fonts
 2f19e2c2f0 chore(cketh): proposal to upgrade ledger
 1446a38f1a fix(icrc1_ledger): include spender in Burn block
 a369837fb0 docs(cketh): improve user documentation
 6fecdf8213 Merge branch 'gdemay/XC-9-docs' into 'master'
 4bb3eb4acb docs(cketh): reformulate docs to target Ethereum mainnet
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout f6d3e13cf080335c7ed7d5f9144f538241fa4122
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```