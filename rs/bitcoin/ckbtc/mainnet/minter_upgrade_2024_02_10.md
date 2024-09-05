# Proposal to upgrade the ckBTC minter canister

Git hash: `0ce2184ddb42ad0c74aa43ccf4f158d120a5608c`

New compressed Wasm hash: `a48766283a361509988faac49da8a8f81669fa69b2481268ee4fc5c30497f900`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/126731

---

## Motivation

* The minter now forms a batch sooner if enough time has laspsed since last batch submission.
* Add a new query method get_known_utxos() that can help determine if update_balance() should be called.
* get_canister_status() also returns query stats.

## Upgrade args

```
git fetch
git checkout 0ce2184ddb42ad0c74aa43ccf4f158d120a5608c
cd rs/bitcoin/ckbtc/minter
didc encode -d '(MinterArg)' -t '(variant {Upgrade})'
```

## Release Notes

```
git log --format=%C(auto) %h %s 43f31c0a1b0d9f9ecbc4e2e5f142c56c7d9b0c7b..0ce2184ddb42ad0c74aa43ccf4f158d120a5608c -- rs/bitcoin/ckbtc/minter
9618e1495 Merge branch 'paulliu/minor-comment-update-balance' into 'master'
f3d614b6e chore: rename ic00_types to management_canister_types
4686c438f feat(ckbtc): Add a query method get_known_utxos XC-54
df4ea62ed chore(ckbtc): Add a comment
1e19fce2c feat(ckbtc): Form a batch when time since last submission exceeds max_time_in_queue XC-36
08d14d255 feat(ckbtc): Remove logs from dashboard
e593c77e4 docs(ckBTC): fix typo in ckBTC readme
fa6adacec Merge branch 'mk/bazel_ic_test2' into 'master'
40db11f8e Chore: Move sandbox env declarations to a common place
5408123d3 doc(ckbtc): fix typo
a8f0d7f61 build: upgrade candid to 0.10
642b11c6a Merge branch 'chmllr/cketh-dashboard-monospace' into 'master'
57580e5eb chore(ckETH): makes the ckETH dashboard use monospace fonts
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 0ce2184ddb42ad0c74aa43ccf4f158d120a5608c
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
