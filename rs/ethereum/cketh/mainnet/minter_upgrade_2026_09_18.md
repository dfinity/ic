# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `2c2c7c99bd526d8c3da51df32aeeb977e852292d`

New compressed Wasm hash: `11a0d3efc6fafd7c8aecbc329ac002d0d62e4645a57daccfc6414e29c6b3cf72`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/143820

---

## Motivation

Upgrade the ckETH/ckERC20 minter to support deposits of ETH from central exchanges. The new flow is triggered by a new endpoint `deposit_eth` and follows the same steps as for depositing ERC-20 tokens described in proposal [143820](https://dashboard.internetcomputer.org/proposal/143820).
Also add the capability for the minter to change the delegation of an already delegated address in case a new deployment of the sweeper smart contract is needed.

## Release Notes

```
git log --format='%C(auto) %h %s' faa1a8a77f71e183b37bb9f25907e90cab7516bc..2c2c7c99bd526d8c3da51df32aeeb977e852292d -- rs/ethereum/cketh/minter
17685bc1da feat(cketh): export metrics for the deposit-from-CEX sweep pipeline (#11576)
d7a9128f01 fix(cketh): guard decode_balance_batch's length arithmetic against overflow (#11566)
0db6e4a4ce feat(cketh): re-delegate deposit addresses to a newly configured sweeper contract (#11554)
a7b362db68 feat(cketh): sweep an address already delegated to the sweeper contract without an authorization (#11550)
7c44970d2c docs(cketh): DEFI-2999: Remove the stale min-deposit test table comment (#11564)
7a063ab524 feat(cketh): read the EIP-7702 delegation of deposit addresses in one eth_call (#11549)
2d37d6b242 feat(cketh): sweep ETH deposits via sweepEthBatch (#11532)
6a7e0a3efc chore: cargo clippy fixes to prepare for the rustc upgrade: 1.97.1 -> 1.98.1 (#11533)
65f0638334 feat(cketh): scan and detect ETH deposits (#11508)
2aeb4b1073 feat(cketh): deposit_eth arms the (account, ETH) pair (#11499)
fe6b10c536 feat(cketh): deposit_eth endpoint deriving the caller's deposit address (#11494)
42d1fb49e2 feat(cketh): add ckBAT to the balance-scan minimum-deposit config (#11503)
7d3c4f1181 fix(cketh): derive the balance-scan batch size from the EIP-3860 initcode limit (#11489)
d1f52e907c fix(cketh): remove duplicated 0x prefix when displaying EventSource (#11480)
 ```

## Upgrade args

```
git fetch
git checkout 2c2c7c99bd526d8c3da51df32aeeb977e852292d
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 2c2c7c99bd526d8c3da51df32aeeb977e852292d
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
