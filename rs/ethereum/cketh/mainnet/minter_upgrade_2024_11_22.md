# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2181ddf2a690ca0262d2d9d0511b093bfa350ece`

New compressed Wasm hash: `47794d7e689c21377b4589f7b304f0d9b8113896b85347aa4e116629cd0941e5`

Upgrade args hash: `242a21d3e36313843547a0620cba9a45b194ad46c7ceb61fb16f92231b2a8652`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/133796

---

## Motivation

This proposal upgrades the ckETH minter to support ledger subaccounts on the minter:
* for deposits:
    * A new helper smart contract was deployed that can be used both for depositing ETH or ERC20 while specifying a full ledger account (principal and subaccount).
    * The minter scraps the logs of the new helper smart contract at the same frequency as the other ones.
    * The previous helper smart contracts are marked as deprecated since the new contract can handle all types of deposits supported by the minter. Future proposals may decide to reduce the frequency at which the logs of the deprecated helper smart contracts are being scraped.
* for withdrawals: subaccounts can be specified when withdrawing ckETH or ckERC20.

## Upgrade args

```
git fetch
git checkout 2181ddf2a690ca0262d2d9d0511b093bfa350ece
cd rs/ethereum/cketh/minter
didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {deposit_with_subaccount_helper_contract_address = opt "0x18901044688D3756C35Ed2b36D93e6a5B8e00E68"; last_deposit_with_subaccount_scraped_block_number = opt 21241175}})' | xxd -r -p | sha256sum
```
* [0x18901044688D3756C35Ed2b36D93e6a5B8e00E68](https://etherscan.io/address/0x18901044688d3756c35ed2b36d93e6a5b8e00e68) is the address of the new helper smart contract supporting deposit of both ckETH and ckERC20 with subaccounts.
* 21241175 is the Ethereum block in which this [helper contract](https://etherscan.io/address/0x18901044688d3756c35ed2b36d93e6a5b8e00e68) was installed.

## Release Notes

```
git log --format='%C(auto) %h %s' 157c4f6fdfa55b40ebde0fe8aad9aa39ca0dae4a..2181ddf2a690ca0262d2d9d0511b093bfa350ece -- rs/ethereum/cketh/minter
2181ddf2a refactor(cketh/ckerc20): mark older helper smart contracts as deprecated (#2747)
95b760ef1 feat(ckerc20): support subaccounts for ckERC20 withdrawals (#2510)
1956e438a feat(cketh): support subaccounts for ckETH withdrawals (#2496)
985126fc4 refactor(cketh/ckerc20): use consistently `LedgerSubaccount` (#2487)
b75dd87ea chore: do not use time of next round in tests (#2455)
46c781579 feat(cketh/ckerc20): consolidate log scrapings (#2449)
219521640 feat(cketh/ckerc20): mint to subaccounts (#2369)
aa7a0739d refactor(cross-chain): rename metrics related to memory (#2372)
15d752c5d chore: avoid reexports from StateMachine tests (#2370)
80d6ecdc4 feat(cketh/ckerc20): Deposit with subaccounts (#2324)
aeb2450d0 refactor(cketh/ckerc20): modular log scraping (#2258)
40e3cc9e6 feat(cketh/ckerc20): Deposit events with subaccounts (#2151)
d481a1b94 feat(cketh/ckerc20): add helper smart contract supporting Subaccounts (#2143)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2181ddf2a690ca0262d2d9d0511b093bfa350ece
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
