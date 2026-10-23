# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `a47e5434753752c1d2972fbc4407d14f88964285`

New compressed Wasm hash: `5ca6c97d52cc3ab86f675674309255b62db91d1e2de592a44795088ba54d35c0`

Upgrade args hash: `5214320100ecc794582e8d3fcfcae6b42e66f0fd16bb81d21c8ef202f7215966`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/139665

---

## Motivation

Update the ckETH minter canister to include the latest code changes:

* Reduce the minimum ETH withdrawal amount by a factor of 6, from 0.03 ETH (`30_000_000_000_000_000` wei) to 0.005 ETH (`5_000_000_000_000_000` wei) — approximately $10 at current prices. The reasoning is as follows:
    * The current minimum dates back to December 2023, when the ckETH minter was installed (see proposal [126171](https://dashboard.internetcomputer.org/proposal/126171)). At that time ETH traded in a similar USD range (around $2000), but Ethereum mainnet transaction fees were averaging $5–$10 per transaction ([source](https://bitinfocharts.com/comparison/ethereum-transactionfees.html#3y)).
    * Today, Ethereum mainnet fees are in the order of cents and rarely exceed $1.
    * As explained [here](https://github.com/dfinity/ic/blob/14382b5abb14b8e7de2bd4a3fb402ba069b82861/rs/ethereum/cketh/docs/cketh.adoc?plain=1#L208), an order-of-magnitude safety margin is preserved so the minter can always submit the transaction even when the Ethereum network is congested and one or more resubmissions are needed (each resubmission requires at least a 10% fee bump). With current Ethereum fees of ~$0.10–$1, a $10 minimum still preserves the ~10× safety margin even after several fee bumps.
* Update the OFAC checklist.


## Release Notes

```
git log --format='%C(auto) %h %s' d13be5a27b3331c4dc8831593eed0e3ec08b260f..a47e5434753752c1d2972fbc4407d14f88964285 -- rs/ethereum/cketh/minter
13a59c1055 chore(defi): remove deprecated ic-cdk imports in ic-cketh-minter (#10290)
63b841f4fa chore: remove unused DeFi rust dependencies (#10281)
7fb12c2e43 ci(defi): check endpoints exported in a canister's WASM against its Candid specification (#10147)
29103b3bdd chore: Updating the block lists for ckBTC and ckETH (#10026)
88a0df635a chore(icrc-ledger-types): DEFI-1894: Switch icrc-ledger-types bazel variants (#9900)
675a14c1af test(defi): move event files to CDN (#9563)
b608c374f2 chore: 42u64 -> 42_u64 (#9523)
a08eb494fe chore(de-fi): Add separator before type suffix in integer literals. (#9433)
56d2c1d738 feat(cketh/ckERC20): stop scraping when minter is stopping  (#8785)
2b1a4d1903 perf(cketh): Benchmark post_upgrade (#8916)
c879313442 fix(cketh): use `try_send` instead of `send` for calls to the EVM RPC canister (#8821)
ccad686b37 chore: Drop unused dependencies (#8470)
d6f2c6fbdd feat(ckETH-minter): DEFI-2231: add decode_ledger_memo endpoint (#8133)
ceb4b666c4 chore: Bump askama version and remove build.rs workaround (#8407)
cc56275206 chore: rust: 1.90.0 -> 1.92.0  (#8124)
3034c5c54b fix: revert "chore: rust 1.90.0 -> 1.91.1 (#8023)" (#8197)
6f73a21b56 chore: rust 1.90.0 -> 1.91.1 (#8023)
c51ed714bc test(ckETH_Minter): DEFI-2559: Add test to verify minter cannot be stopped while it is scraping blocks (#7962)
 ```

## Upgrade args

```
git fetch
git checkout a47e5434753752c1d2972fbc4407d14f88964285
didc encode -d rs/ethereum/cketh/minter/cketh_minter.did -t '(MinterArg)' '(variant { UpgradeArg = record { minimum_withdrawal_amount = opt (5_000_000_000_000_000 : nat)} })' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout a47e5434753752c1d2972fbc4407d14f88964285
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
