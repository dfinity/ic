# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `faa1a8a77f71e183b37bb9f25907e90cab7516bc`

New compressed Wasm hash: `da607e433d408192428aaa14373efbd8dcb083a0e7184099b909b7a758971b07`

Upgrade args hash: `96abd4bd52e5a54759176fd430188058b7dec6b90d807d183bf18dad33fabdf7`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/141979

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
git log --format='%C(auto) %h %s' a47e5434753752c1d2972fbc4407d14f88964285..faa1a8a77f71e183b37bb9f25907e90cab7516bc -- rs/ethereum/cketh/minter
faa1a8a77f feat(cketh): accept and sweep plain ETH at delegated deposit addresses (#11449)
51d004431f test(cketh): derive e2e sweep parameters from get_minter_info and re-send a stale authorization (#11374)
b61f969cc5 chore(cketh): drop the deprecated ethers-core dependency (#11304)
55cd41e9c7 refactor(cketh): encode the ABI calls the tests check with alloy (#11303)
bee44d8cd1 feat: drop 'thousands' crate (#11395)
1c7b7f0f14 feat(cketh): check the EIP-7702 encoding against alloy and drop the decoder (#11302)
7cff01e00f refactor(cketh): cross-check the minter's transactions against alloy (#11301)
101749450b refactor(cketh): mock the EVM RPC responses with alloy's RPC types (#11300)
2c40e8d4e5 feat(cketh): sweeper funding observability (#11094)
b22e4ed67e fix(cketh): provision sweep gas out of the sweeper balance bound (#11342)
ba61ed07f3 test(cketh): credit twenty CEX deposits through one EIP-7702 sweep per token (#11363)
8eb36dc78b feat(cketh): enqueue the sweep a signed batch has become (#11362)
13f49f56b8 feat(cketh): sign the authorizations a batched sweep needs (#11360)
e2a4283417 feat(cketh): sign the attestations a batched sweep needs (#11359)
0ff3907dba feat(cketh): task skeleton to create sweeper requests (#11347)
24345e0cfc refactor(cketh): move the sweeper pipeline into AutomaticDeposits (#11351)
62f84509af refactor(cketh): make event recording generic over a TimeProvider (#11345)
1614219ff6 feat(cketh): sweeper fee-funding task, with an end-to-end test (#11086)
d4ab79c040 feat(cketh): remember the attestations the minter has signed (#11319)
4651475c33 feat(cketh): encode the delegate's batch sweep call (#11257)
e16d27df7f feat(cketh): report the token's minimum deposit amount from deposit_erc20 (#11296)
449a91fad4 feat(cketh): attest a deposit address' account so anyone can sweep it (#11256)
b546d76079 fix(cketh): recover a signature against the key that made it (#11254)
6c76ca8169 feat(cketh): drive the sweeper transaction pipeline from its own timer task (#11237)
82b2a6643b feat(cketh): install a deposit address' delegation with its first sweep (#11250)
5769a110c4 feat(cketh): expose per-token minimum deposit amounts in MinterInfo (#11251)
b1e01edb90 feat(cketh): expose the sweeper address in MinterInfo (#11240)
34dc0bccce feat(cketh): give the sweeper address its own transaction pipeline (#11144)
948f633779 refactor(cketh): make the transaction pipeline generic over its request (#11178)
6ce8e37220 feat(cketh): burn-first accounting for sweeper fee funding (#11083)
e57e2e7c1b refactor(cketh): extract TransactionPipeline from WithdrawalTransactions (#11190)
b074ca2612 refactor(cketh): rename EthTransactions to WithdrawalTransactions and hide its fields (#11177)
0b8acf2d14 feat(cketh): add the SweeperFunding withdrawal-request variant (#11072)
404f594538 test(cketh): refresh the mainnet and Sepolia replay events to v2 (#11164)
e0823e1ca7 test(cketh): build the live balance-scan harness on the shared fixtures (#11124)
28e60fba55 feat(cketh): configure and expose the sweeper contract address (#11145)
8aa4680e37 feat(cketh): per-(deposit address, ERC-20) deposit granularity (#11128)
6ca30003de feat: migrate to ic-cdk 0.20 (#11069)
11677e3d8a feat(cketh): move funded deposit addresses to a balance-sweep queue (#10946)
53efbe5878 test(cketh): migrate integration tests to PocketIC (#10955)
e43fa37969 test(cketh): deduplicate signed-transaction and transaction-hash literals in integration tests (#10950)
e156e901f2 feat(cketh): read a native ETH balance via the EVM RPC canister (#11060)
c269e16096 test(cketh): end-to-end balance scan against a live anvil node (#10947)
0ac65bf3e1 feat(cketh): detect deposits above minimum (#10873)
522634fb44 feat(cketh): balance-scan scheduling layer (#10881)
37755a2ccb feat(cketh): deposit_erc20 endpoint (derive + store deposit addresses) (#10729)
935c65d4bb feat(cketh): TimedSizedMap bounded, time-expiring map (#10705)
6ed0116324 chore: move all crate definitions into workspace (#10812)
f245d740fb chore: use workspace crates everywhere (#10809)
194c6da295 chore: cargo clippy fixes to prepare for the rustc upgrade: 1.95.0 -> 1.97.0 (#10732)
5ee93a4131 chore: bump rustc to v1.95.0 (#10698)
24c5c2a1c6 test: end-to-end deposit-from-CEX EIP-7702 sweep demo against a local Ethereum node (#10670)
26d21efc07 feat: per-account deposit-address derivation for the ckETH/ckERC20 minter (#10685)
d202c1f06f fix: revert "chore: bump rustc to v1.95.0 (#10390)" (#10697)
17c50a475b chore: bump rustc to v1.95.0 (#10390)
5297f59ed2 chore: prepare for rustc version bump to v1.95.0 (#10637)
ce7b41068d feat: EIP-7702 (SetCode) transaction layer for the ckETH/ckERC20 minter (#10671)
 ```

## Upgrade args

```
git fetch
git checkout faa1a8a77f71e183b37bb9f25907e90cab7516bc
didc encode -d rs/ethereum/cketh/minter/cketh_minter.did -t '(MinterArg)' '(variant { UpgradeArg = record { ethereum_sweeper_contract_address = opt "0x939743E3d48eB541317B2c6Ad862f5283899023b"; next_sweeper_transaction_nonce = opt (0 : nat)} })' | xxd -r -p | sha256sum
```

* [0x939743E3d48eB541317B2c6Ad862f5283899023b](https://etherscan.io/address/0x939743e3d48eb541317b2c6ad862f5283899023b) is the sweeper contract address initialized with the address of the deposit helper smart contract [0x18901044688D3756C35Ed2b36D93e6a5B8e00E68](https://etherscan.io/address/0x18901044688D3756C35Ed2b36D93e6a5B8e00E68).
* The address controlled by the minter to make sweep transactions did not create yet any transaction and so its next transaction nonce is `0`.

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout faa1a8a77f71e183b37bb9f25907e90cab7516bc
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
