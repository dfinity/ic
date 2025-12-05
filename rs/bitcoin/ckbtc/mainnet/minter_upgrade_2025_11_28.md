# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `d13be5a27b3331c4dc8831593eed0e3ec08b260f`

New compressed Wasm hash: `fb6bd17ca009b3ee4f509ab7972b8b84ada3444c700b35ad03603103f806aace`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/137930

---

## Motivation
The ckBTC minter does not accept deposits from or withdrawals to Bitcoin addresses on its internal blocklist.
This upgrade of the ckBTC minter updates the blocklist based on the latest [OFAC SDN list](https://sanctionslist.ofac.treas.gov/Home/SdnList).


## Release Notes

```
git log --format='%C(auto) %h %s' b6cf1a858dfa1634e763eff203a709afbd1d8bb0..d13be5a27b3331c4dc8831593eed0e3ec08b260f -- rs/bitcoin/ckbtc/minter
03befefb98 feat(ckdoge): Upgrade of minter (#7933)
bc357afaa3 perf(ckbtc): Reduce the number of instructions to build an unsigned transaction by a factor 5x to 600x (#7866)
2c177cd030 perf(ckbtc): canbench `build_unsigned_transaction_from_inputs` (#7782)
c98c9cee89 feat(ckdoge): add `estimate_withdrawal_fee` query endpoint (#7801)
b6af146665 chore: ic-cdk v0.19 & ic-cdk-timers v1.0.0 (#7494)
3f92b30bf1 test(ckbtc): update mainnet events for test purposes (#7789)
1f8f7bd405 fix(ckbtc): improve transaction fee estimation (#7741)
00a5f4688d fix(ckdoge): use correct transaction fees  (#7660)
0f2ecf9aac chore: use versioned name for duplicated crates (#7687)
d55e60b347 fix(ckdoge): finalization of transactions sent by the minter (#7589)
5feafc544f feat(ckdoge): `get_known_utxos` endpoint (#7627)
f6ddb94cca fix(ckbtc): time estimate for finalization (#7621)
f7348c6d9d feat(ckdoge): withdrawal (#7360)
2c8361f117 feat(ckdoge): retrieve fee percentile from dogecoin canister (#7366)
d29acdbf1e feat(ckdoge): endpoints to retrieve events, metrics, dashboard and logs (#7280)
d1e0b6e7b4 chore(ckbtc): reinstate the previous test_transaction_resubmission_finalize_new test (#5858)
c995070586 refactor(ckbtc): use `canlog` for logging (#7328)
b358d80102 chore: upgrade rust: 1.89.0 -> 1.90.0 (#7322)
52c88e161e feat(ckdoge): deposit flow with `update_balance` (#7095)
08717638d4 feat(ckdoge): derive Dogecoin address for deposits (#7066)
5dcdf2ef89 feat(dogecoin): facade for ckdoge minter canister (#6814)
2f56f172a1 chore: bump rust to 1.89 (#6758)
d8868a672d chore(XC): remove deprecation from `ic-cdk` in `ic-ckbtc-minter` (#6761)
b9221277cd chore: bumping edition to 2024 (#6715)
5c143d81fa feat: migrate to edition 2024 (#6667)
4d76b91971 test(ckbtc): use `lazy_static` to improve runtime of replay_events tests (#6516)
97ae0c8647 chore: tag //rs/bitcoin/ckbtc/minter:ckbtc_minter_replay_events_tests as a long_test (#6484)
12f93cd3f3 fix(ckbtc): adapt fee when reimbursing pending withdrawal requests (#6291)
49d659c29d feat: Unify ic-cdk to v0.18.6 (#6264)
 ```

## Upgrade args

```
git fetch
git checkout d13be5a27b3331c4dc8831593eed0e3ec08b260f
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d13be5a27b3331c4dc8831593eed0e3ec08b260f
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
