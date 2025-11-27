# Proposal to upgrade the ckBTC ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `3f3d9bfac750f82f424185ac5b32a756cfd45ad9`

New compressed Wasm hash: `24e6b0b09ba44b1123453877994bb59ce75555c2e33f19f58163a3e0c6e62bd1`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/137360

---

## Motivation

Upgrade the ckBTC ledger canister to the latest
version [ledger-suite-icrc-2025-09-01](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2025-09-01).

## Release Notes

```
git log --format='%C(auto) %h %s' 83923a194d39835e8a7d9549f9f0831b962a60c2..3f3d9bfac750f82f424185ac5b32a756cfd45ad9 -- rs/ledger_suite/icrc1/ledger
e3857ed56a feat(ICRC-Ledger): FI-1653: Ensure upgrade u64 <-> u256 fails (#6486)
19a45d5b7f test(ICRC_Ledger): FI-1834: Add check for number of blocks returned in test_icrc3_get_blocks (#6399)
f322cac905 fix(Ledgers): verify fee when generating ICRC-21 consent message (#6381)
49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
cddf2f8a99 chore(ICRC_Ledger): FI-1747: Clean up ICRC-106 migration code (#5627)
2ee6ac954b chore(Ledgers): format did files with default formatter (#6235)
3889808133 feat(ledgers): FI-1659: fix the generic ICRC-21 message, add FieldsDisplay (#5563)
6045144d84 chore(Ledgers): FI-1252: Remove unused dependencies (#6193)
a4c1c9bce1 chore: update rust to 1.88.0 (#6045)
d890a928d9 test(ICRC_Ledger): FI-1793: Fix allowance checking flakiness in golden state tests (#5914)
e73c4081d3 test(ICRC_Ledger): FI-1592: Add test with unsupported ledger init args (#5452)
6e91324ffc chore(IDX): bump timeout for ledger_test (#5682)
 ```

## Upgrade args

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3f3d9bfac750f82f424185ac5b32a756cfd45ad9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger.wasm.gz
```
