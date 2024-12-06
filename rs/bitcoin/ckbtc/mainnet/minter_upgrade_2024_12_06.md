# Proposal to upgrade the ckBTC minter canister to start using the Bitcoin Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `9849a2f03af855d09ac42f5949393c86df3d9c47`

New compressed Wasm hash: `ba096af5f4c4459e6f4ba7c3e663f2287aec9ae359fc94faa35f87e6a4114a28`

Upgrade args hash: `90fcd3ef7d62d0eb77d520dbdc0fe923bee5061930de9299e579bc080fd0a858`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/134172

---

## Motivation

Upgrade the ckBTC minter canister to use the BTC Checker canister instead of the KYT canister.

The BTC Checker canister (`oltsj-fqaaa-aaaar-qal5q-cai`) is a new canister that is installed by proposal XXXXX.
It implements checks for Bitcoin transactions and addresses against the OFAC (https://sanctionssearch.ofac.treas.gov/) list.
BTC to ckBTC deposits that had previously quarantined or ignored UTXOs can be retried by the user.
Such deposits will be re-evaluated under the new approach.

More discussions on this change can be found in the forum thread https://forum.dfinity.org/t/ckbtc-and-kyt-compliance/18754.

As a result, the check fee per deposit request is now reduced to 100 satoshi, and withdrawals will no longer incur any check fee.

## Upgrade args

```
git fetch
git checkout 9849a2f03af855d09ac42f5949393c86df3d9c47
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = opt record { check_fee = opt 100; btc_checker_principal = opt principal "oltsj-fqaaa-aaaar-qal5q-cai"; } })' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 511ad1cf505003e33baf0ce0eefa0168aad91bf1..9849a2f03af855d09ac42f5949393c86df3d9c47 -- rs/bitcoin/ckbtc/minter
ed8542884d refactor(ckbtc): use IC CDK to interact with Bitcoin canister (#2921)
c2871b308f fix(ckbtc): compute min_withdrawal_amount using check_fee from state (#3000)
4ac53c2c46 feat(ckbtc): add timestamps to suspended UTXOs (#2939)
2161453e93 chore(ckbtc): Rename btc kyt canister to btc checker canister (#2966)
2e2fff1d2e refactor(ckbtc): reduce minter fee (#2861)
6f1be0fb08 feat(ckbtc): Add account to discarded UTXOs (#2762)
4552e6a825 chore(ckbtc): Rename new_kyt_principal to kyt_principal (#2706)
7d81347658 feat(ckbtc): re-evaluate discarded UTXOs (#2674)
0dc55e08ab feat(ckbtc): Use the new KYT canister in ckbtc deposit flow  (#2304)
e6d986be32 fix(ckbtc): ensure tasks are always rescheduled (#2630)
2244bbbcbc feat(ckbtc): Remove reimbursement handling in retrieve_btc_with_approval (#2559)
e224f9e438 test(ckbtc): replay events (#2564)
8f7692a468 feat(ckbtc): Use the new KYT canister in ckbtc withdrawal flow (#2240)
b79edc2d0e fix(ckbtc): Fix a problem with retrieve_btc_min_amount setting (#2435)
aa7a0739dc refactor(cross-chain): rename metrics related to memory (#2372)
15d752c5dd chore: avoid reexports from StateMachine tests (#2370)
c5e6242f5d chore: remove unneeded clippy allows (#2326)
69e9f07630 chore: do not pin to crate versions (#2073)
fcbc91f0a5 chore: update `ic-cdk` to 0.16.0 (#1868)
6ed86361e0 chore: duplicate btc header validation to main repo #769 (#1766)
3bbabefb70 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 9849a2f03af855d09ac42f5949393c86df3d9c47
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
