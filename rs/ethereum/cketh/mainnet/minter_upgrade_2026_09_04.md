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
Currently, depositing an ERC-20 token requires calling a smart contract ([0x18901044688D3756C35Ed2b36D93e6a5B8e00E68](https://etherscan.io/address/0x18901044688D3756C35Ed2b36D93e6a5B8e00E68)) with parameters specifying the intended owner on the Internet Computer (principal and subaccount), which is typically not supported by central exchanges.

At a high level, the new deposit flow for Alice would look like this:
1. She notifies the minter of her intention of depositing USDT by calling the new endpoint `deposit_erc20`, which returns Alice's dedicated deposit address on Ethereum. The address is derived from the minter's threshold-ECDSA key, so funds sent there are under the minter's control from the moment they arrive.
2. Alice has 24 hours to transfer USDT from her account on her favorite central exchange to the deposit address. The window can be re-armed by calling `deposit_erc20` again, and funds arriving after it closed are not lost: scanning simply resumes with the next registration.
3. The minter scans the registered deposit addresses and if an address has enough tokens (roughly $10) it will be swept, which consists of the following steps:
    1. The minter signs an attestation with the deposit address' own threshold-ECDSA key, binding the deposit address to a (principal, subaccount) on the Internet Computer.
    2. The minter signs an [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) authorization to delegate the deposit address to the sweeper contract [0x939743E3d48eB541317B2c6Ad862f5283899023b](https://etherscan.io/address/0x939743e3d48eb541317b2c6ad862f5283899023b). This happens once per deposit address: the delegation persists, so later sweeps of the same address need no new authorization.
    3. Finally, the minter sends the sweep transaction to the sweeper contract at [0x939743E3d48eB541317B2c6Ad862f5283899023b](https://etherscan.io/address/0x939743e3d48eb541317b2c6ad862f5283899023b). Running as the deposit address' delegate, the sweeper contract verifies that the attestation recovers to the deposit address itself and calls the existing deposit helper smart contract with the attested principal and subaccount, so that the exact same deposit flow occurs as if the user had called the deposit helper smart contract directly. This has the benefit that the same `ReceivedEthOrErc20` events are emitted and the minter's main address ([0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80](https://etherscan.io/address/0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80)) holds the funds.

Key design decisions:
1. The 1:1 backing of ckETH is not affected: the gas for sweep transactions is paid by burning ckETH from the minter's fee subaccount on the ckETH ledger, so the cumulative amount burned always covers the cumulative ETH spent on sweeps.
2. Sweep transactions are sent from a dedicated sweeper address, distinct from the minter's main address ([0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80](https://etherscan.io/address/0xb25eA1D493B49a1DeD42aC5B1208cC618f9A9B80)) holding the funds, so that a stuck sweep transaction does not block the withdrawal pipeline (Ethereum nonces are sequential per address).
3. Sweeping is permissionless: once a deposit address is delegated, anyone can call the sweep methods to forward the tokens, provided the input attestation is correct — an attestation only ever credits the account it was created for.

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
