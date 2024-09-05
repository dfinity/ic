# Proposal to upgrade the ckETH minter canister

Git hash: `4472b0064d347a88649beb526214fde204f906fb`

New compressed Wasm hash: `8108f9f7d64577e0c29c0359b689675863ab53b472796de71276f0d2467ddf3d`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/128365

---

## Motivation
This proposal upgrades the ckETH minter to enable the ckERC20 feature on the minter. Adding support for concrete tokens (e.g., USDC), will be done in separate upgrade proposals targeting the ledger suite orchestrator, which upon execution will then contact the minter via the new restricted endpoint `add_ckerc20_token`.


## Upgrade args

```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {ledger_suite_orchestrator_id = opt principal "vxkom-oyaaa-aaaar-qafda-cai"; erc20_helper_contract_address = opt "0x6abDA0438307733FC299e9C229FD3cc074bD8cC0"; last_erc20_scraped_block_number = opt 19_817_725;}})'
```
* [`vxkom-oyaaa-aaaar-qafda-cai`](https://dashboard.internetcomputer.org/canister/vxkom-oyaaa-aaaar-qafda-cai) is the ledger suite orchestrator.
* `19_817_725` is the Ethereum block in which the [ckERC20 helper contract](https://etherscan.io/address/0x6abDA0438307733FC299e9C229FD3cc074bD8cC0) was installed.

## Release Notes

```
git log --format=%C(auto) %h %s 7076b5ea0a173c990d25ee0fa19216c4b47e675c..4472b0064d347a88649beb526214fde204f906fb -- rs/ethereum/cketh/minter
de1bd6522 fix(ckerc20): Improve robustness of multi-call strategy
792faa8aa fix(ckerc20): fix label clash in metrics
1b0c10525 feat(ckerc20): Add a withdrawal_status method to minter XC-78
37b0eb74c chore(ckerc20): Add metrics for ERC-20 balances
42e6f7bf8 fix(ckerc20): Skip scraping logs when there is no token contract yet
697884128 fix(ckerc20): use OpenZeppelin `SafeERC20` for deposit helper smart contract
d31e4c5aa Merge branch 'gdemay/XC-108-guard-against-potential-double-minting-reimbursements' into 'master'
df1c9e31d fix(ckerc20): Prevent with a guard potential double minting of ckETH and ckERC20 during reimbursements [override-didc-check]
ecfd4b7ed chore(cketh): Update PublicNode urls
70a331968 fix(ckerc20): add back smart_contract_address to MinterInfo
78e7b138c fix(ckerc20): Prevent with a guard potential double minting of ckETH and ckERC20 [override-didc-check]
7957dab20 chore: rules_rust 0.33.0 -> 0.42.1
dd8247fc8 Merge branch 'gdemay/XC-99-test-upgrade' into 'master'
2178478e9 test(ckerc20): Ensure that minter events can be replayed from current state
5134e0c6d feat(ckerc20): Deploy ckERC20 for Ethereum Sepolia
253318f3c Merge branch 'gdemay/XC-82-dashboard-reimbursed' into 'master'
185663f48 feat(ckerc20): Display reimbursed ckERC20 withdrawals on minter dashboard
9d80230d0 fix(ckerc20): error when ckERC20 withdrawal amount is too low instead of wrongly panicking [override-didc-check]
fd03bd32c Merge branch 'gdemay/XC-96-ckerc20-withdrawal-without-reimbursements' into 'master'
860af97c5 feat(ckerc20): ckERC20 withdrawals without reimbursement of transaction fees [override-didc-check]
2a63bb305 Merge branch 'gdemay/XC-99-dashboard-erc20-balances' into 'master'
0a3de0e57 feat(ckerc20): Display balances of supported ERC-20 tokens on minter dashboard
e5ca19136 feat(ckerc20): Optimize gas fee estimation
478571dfc fix: make time in StateMachine tests strictly monotone
58ce76f62 feat(ckerc20): Display ERC20 withdrawals on dashboard
53146e75e test(ckerc20): additional integration tests for ckERC20 withdrawals
9f699811e Merge branch 'paulliu/ckerc20-deposit-dashboard' into 'master'
641af2ede feat(ckerc20): Display ERC20 deposit events on dashboard XC-69
83de96866 feat(ckerc20): Track ERC-20 balances
7c05b1648 Merge branch 'gdemay/XC-47-fail-stoping-minter' into 'master'
deb0b804a fix(ckerc20): the ledger suite orchestrator retries to notify a stopped minter of a new ERC-20 token
3a8ef529c Merge branch 'gdemay/XC-46-fix-minter-info' into 'master'
1ae707c85 fix(cketh): Make `supported_ckerc20_tokens` in `MinterInfo` optional  [override-didc-check]
d0979337d fix(ckerc20): Account for minter's work when reimbursing unused transaction fees for ckERC20 withdrawals
b405a0f06 refactor(ckerc20): error type `WithdrawErc20Error` includes the ckETH burn index [override-didc-check]
065a373a6 test(ckerc20): state machine test for ckERC20 withdrawal
f6a556a24 Merge branch 'gdemay/XC-59-ckerc20-withdrawal-tests' into 'master'
7b935fe5d test(ckerc20): State machine tests for depositing ckETH and ckERC20
2ebeecf76 chore: Move assert_matches dependency to workspace
b412b7931 chore: Move `hex` dependency to workspace
c951a020f feat(ckerc20): reimburse failed ckERC20 wtihdrawals [override-didc-check]
89b17c50a Merge branch 'gdemay/XC-59-fix-test-constants' into 'master'
24da9afa0 test(cketh): use production values for minimum withdrawal amount and ledger transaction fee
b20584137 refactor(ckerc20): Generalize `ReimbursementRequest` and `Reimbursed`
5eaee924e refactor(ckerc20): add ckERC20 ledger ID to withdrawal request
b9a58c9de fix(ckerc20): persist last erc20 scraped block number across upgrades [override-didc-check] XC-46
0db5f23e8 Merge branch 'gdemay/XC-59-ckerc20-resubmit' into 'master'
3b6a10ca9 feat(ckerc20): Resubmit ckERC20 withdrawal requests
7edca307f Merge branch 'gdemay/XC-85-llama-nodes' into 'master'
9000c62b1 fix(cketh): Change Cloudflare JSON-RPC provider to LlamaNodes (master)
f277a21cd feat(ckerc20): create Ethereum transactions for ckERC20 withdrawals [override-didc-check]
44b4017cb fix(ckerc20): Fix wrong display order in supported_ckerc20_tokens
e7656cf25 feat(ckerc20): Mint ckERC20 tokens [override-didc-check] XC-46
1cc624107 Merge branch 'dsharifi/num-traits-workspace-dep' into 'master'
0fe5aff1e chore: Move num-traits dependency to workspace
b8b861776 feat(ckerc20): endpoint `withdraw_erc20` to start a ckERC20 withdrawal [override-didc-check]
763c1fa0f refactor(cketh): simplify ledger burn operation
8763c4932 feat(ckerc20): Ledger burn memos for ckERC20 withdrawals
56579e061 test(ckerc20): stop ckETH minter before upgrading it in state machine tests
2be4d5597 feat(cketh): scrape logs of ERC-20 helper contract [override-didc-check] XC-45
e96bd224e feat(cketh): Support both single and mutliple topics in GetLogsParam XC-76
0a0f6e38c build: use workspace version for thiserror crate
e5c6356b5 Merge branch 'mraszyk/bump-ic-cdk' into 'master'
1d9d4bc30 chore: bump ic-cdk to 0.12.1
a7bce35f5 test(ckerc20): Integration test infrastructure for ckERC20
90d3c35c9 feat(ckerc20): add `add_ckerc20_token` endpoint on the ckETH minter [override-didc-check]
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
