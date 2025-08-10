# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9`

New compressed Wasm hash: `8a5c77ddafee85bee18e3fa76c11922ed5b7bd11f81c2d66b578b0c1b00f5b23`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/134264

---

## Motivation

Fix an undesired breaking changed introduced by proposal [134264](https://dashboard.internetcomputer.org/proposal/134264) :

1. The fields `eth_helper_contract_address` and `erc20_helper_contract_address` in `get_minter_info` were wrongly reused to point to the new helper smart contract [0x18901044688D3756C35Ed2b36D93e6a5B8e00E68](https://etherscan.io/address/0x18901044688D3756C35Ed2b36D93e6a5B8e00E68) that supports deposit with subaccounts and that was added as part of proposal [134264](https://dashboard.internetcomputer.org/proposal/134264).
2. This broke clients that relied on that information to make deposit of ETH or ERC-20 because the new helper smart contract has a different ABI. This is visible by such a [transaction](https://etherscan.io/tx/0x0968b25814221719bf966cf4bbd2de8290ed2ab42c049d451d64e46812d1574e), where the transaction tried to call the method `deposit` (`0xb214faa5`) that does exist on the [deprecated ETH helper smart contract](https://etherscan.io/address/0x7574eB42cA208A4f6960ECCAfDF186D627dCC175) but doesn't on the new contract (it should have been `depositEth` (`0x17c819c4`)).
3. The fix simply consists in reverting the changes regarding the values of the fields `eth_helper_contract_address` and `erc20_helper_contract_address` in `get_minter_info` (so that they point back to [0x7574eB42cA208A4f6960ECCAfDF186D627dCC175](https://etherscan.io/address/0x7574eB42cA208A4f6960ECCAfDF186D627dCC175) and [0x6abDA0438307733FC299e9C229FD3cc074bD8cC0](https://etherscan.io/address/0x6abDA0438307733FC299e9C229FD3cc074bD8cC0), respectively) and adding new fields to contain the state of the log scraping (address and last scraped block number) for the new helper smart contract.

## Upgrade args

```
git fetch
git checkout 5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9
cd rs/ethereum/cketh/minter
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 2181ddf2a690ca0262d2d9d0511b093bfa350ece..5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9 -- rs/ethereum/cketh/minter
5ce01d0a8 fix(cketh): Undo breaking change in `get_minter_info` (#2907)
68d1088d5 chore(XC-48): extract cketh minter minicbor encoder and decoders into a separate library (#2769)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
