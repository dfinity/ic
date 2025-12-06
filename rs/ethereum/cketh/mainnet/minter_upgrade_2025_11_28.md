# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `d13be5a27b3331c4dc8831593eed0e3ec08b260f`

New compressed Wasm hash: `bec1be12f91dd141262cabfe2033183b717d2f6ddcee3f39ab52a11df2a39dcb`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/136787

---

## Motivation
The ckETH minter does not accept deposits from or withdrawals to Ethereum addresses on its internal blocklist.
This upgrade of the ckETH minter updates the blocklist based on the latest [OFAC SDN list](https://sanctionslist.ofac.treas.gov/Home/SdnList).


## Release Notes

```
git log --format='%C(auto) %h %s' bb6e758c739768ef6713f9f3be2df47884544900..d13be5a27b3331c4dc8831593eed0e3ec08b260f -- rs/ethereum/cketh/minter
b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
348680b6ba chore: Update the ckBTC and ckETH blocklists (#7639)
ccf0893ffa refactor(cketh/ckerc20): use `evm_rpc_client` in ckETH minter (#7112)
fc7f7307be refactor(cketh/ckerc20): multi RPC results reduction (#7152)
aec0573069 feat(ICRC-Index): FI-1759: stop indexing and report error in case of unknown block (#6996)
c67b20bf06 chore: remove rules_sol (#7292)
7a9b006a27 refactor(cketh/ckerc20): use `evm_rpc_types` crate directly (#7154)
a45cc12f7a chore: remove rules_closure (#7173)
2f56f172a1 chore: bump rust to 1.89 (#6758)
b9221277cd chore: bumping edition to 2024 (#6715)
5c143d81fa feat: migrate to edition 2024 (#6667)
49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
9bceb44972 chore(cross-chain): use `evm_rpc_types` v2.0.0 (#6238)
8f6f484f57 chore: increase cketh test timeout (#5905)
93a18ceb98 chore(cketh): use GetLogsRpcConfig (#5864)
8bb4b836b6 refactor(cketh): clean up eth_rpc.rs (#5717)
7ed93cf223 refactor(cketh): replace local types with evm_rpc_types (#5428)
4ac814456f refactor(cketh): remove SingleCallError and HttpOutcallError, remove redundant reduction in `eth_get_finalized_transaction_count` and `eth_get_block_by_number` (#5268)
 ```

## Upgrade args

```
git fetch
git checkout d13be5a27b3331c4dc8831593eed0e3ec08b260f
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d13be5a27b3331c4dc8831593eed0e3ec08b260f
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
