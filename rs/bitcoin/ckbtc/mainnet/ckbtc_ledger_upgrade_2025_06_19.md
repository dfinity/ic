# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `83923a194d39835e8a7d9549f9f0831b962a60c2`

New compressed Wasm hash: `da09eb07393d5068879cdf212f47012cd23aaddc0fa49122cab2da657135f06e`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/136742

---

## Motivation

Upgrade ckBTC ledger canister to the latest
version [ledger-suite-icrc-2025-06-19](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-06-19).

## Release Notes

```
git log --format='%C(auto) %h %s' fda8ae420732b21f0ddbbcc5dfbd4ddbe0db9c26..83923a194d39835e8a7d9549f9f0831b962a60c2 -- rs/ledger_suite/icrc1/ledger
83923a194d feat(ICRC_Ledger): FI-1771: Add 1xfer to icrc3_supported_block_types (#5608)
00713b9827 feat(ICRC_Ledger): FI-1604: Set index in existing SNS and ck ledgers (#5237)
3671acb49d chore: upgrade rust: 1.85.1 -> 1.86.0 (again) (#5453)
995f15aed0 feat(Ledgers): FI-1666: Set upper limit for num_blocks_to_archive (#5215)
e94aa05386 test(Ledgers): FI-1652: Add instruction limit test for ledger archiving (#4961)
02571e8215 feat(ICRC_Ledger): FI-1592: Implement ICRC-106 in the ICRC ledger (#2857)
029ebf5c44 chore: Upgrade canbench to 0.15.0 (#5356)
2cc5b2479b chore(ICRC_Ledger): FI-1726: Use test_strategy instead of proptest macro for ICRC1 ledger suite tests (#5039)
 ```

## Upgrade args

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 83923a194d39835e8a7d9549f9f0831b962a60c2
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```