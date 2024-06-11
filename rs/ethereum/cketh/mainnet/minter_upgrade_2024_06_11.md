# Proposal to upgrade the ckETH minter canister

Git hash: `7fbb84aad7188d1d5b3e17b170997c29d1598cb8`

New compressed Wasm hash: `9a757b2aa2f9bf0c7ef23b13c036315eea75c1c7a0f767ccc2d189be64a4d2a1`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/129689

---

## Motivation
This is a regular upgrade containing minor improvements.

## Upgrade args

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {}})'
```

## Release Notes

```
git log --format=%C(auto) %h %s 4472b0064d347a88649beb526214fde204f906fb..7fbb84aad7188d1d5b3e17b170997c29d1598cb8 -- rs/ethereum/cketh/minter
c71753399 Merge branch 'mathias-FI-1314-use-stable64-size-in-canister-metrics' into 'master'
a5c8d79ad feat(FI): FI-1314: Use ic_cdk::api::stable::stable64_size() instead of stable_size() for canister metrics
6e69046a0 Merge branch 'paulliu/fix-skipped-blocks' into 'master'
db5f48919 fix(ckerc20): Record skipped blocks separately for each helper contract XC-125
f7f0453b2 refactor(ckerc20): More efficient data structure to store ckERC20 tokens
2d7dfc013 chore: upgrade tempfile version and use the workspace. version everywhere
f45570024 chore: use the rand version from the Cargo workspace
68e8bcbde feat(cketh): add ckETH ledger ID to `get_minter_info`
2966cd407 feat(ckerc20): Add metric for `last_erc20_scraped_block_number`
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
