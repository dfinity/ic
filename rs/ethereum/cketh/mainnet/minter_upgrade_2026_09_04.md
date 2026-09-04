# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `a47e5434753752c1d2972fbc4407d14f88964285`

New compressed Wasm hash: `5ca6c97d52cc3ab86f675674309255b62db91d1e2de592a44795088ba54d35c0`

Upgrade args hash: `5214320100ecc794582e8d3fcfcae6b42e66f0fd16bb81d21c8ef202f7215966`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/139665

---

## Motivation

Upgrade the ckETH/ckERC20 minter to support deposits of ERC-20 tokens from central exchanges.
Currently, depositing an ERC-20 tokens requires calling a smart contract ([0x18901044688D3756C35Ed2b36D93e6a5B8e00E68](https://etherscan.io/address/0x18901044688D3756C35Ed2b36D93e6a5B8e00E68)) with parameters specifying the intended owner on the Internet Computer (principal and subaccount), which is typically not supported from central exchanges.

At a high level, the new deposit flow for Alice would look like this:
1. She notifies the minter of her intention of depositing USDT by calling the new endpoint `deposit_erc20`, which returns Alice's dedicated deposit address on Ethereum.
2. Alice has roughly 24H to do a transfer of USDT from her account on her favorite central exchange to the deposit address.
3. The minter scans the registered deposit addresses and if an address as enough tokens (roughly $10) it will be swept, which consists of the following steps:
    1. The minter signs an attestation, binding the deposit address to a (principal, subaccount) on the Internet Computer
    2. The minter signs an [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) authorization to delegate the deposit address to the sweeper contract `0xREPLACE_ME`.
    3. Finally, the minter makes an [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) transaction to the sweeper contract at `0xREPLACE_ME`. The sweeper contract verifies the attestation and calls the existing deposit helper smart contract with the given principal and subaccount, so that the exact same deposit flow occurs as if the user had called the deposit helper smart contract directly. This has the benefits that the same events `ReceivedEthOrErc20` are emitted and the minter's main address ([0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80](https://etherscan.io/address/0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80)) holds the funds.

Key design decisions:
1. Backing of ckETH is not affected: cost of sweeping transactions is taken from the minter's fee subaccount on the ledger.
2. Sweeping transactions use a different address than the minter's main address ([0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80](https://etherscan.io/address/0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80)) holding the funds so that a blocking sweeping transaction does not block the main transaction pipeline (due to Ethereum sequential nonces).
3. Sweeping is permissionless: once a deposit address is delegated, anyone can call the sweep methods to forwards the tokens, provided the input attestation is correct.

More details and diagrams can be found in the [design document](https://github.com/dfinity/ic/blob/master/rs/ethereum/cketh/docs/deposit_from_cex.md).

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
