# Proposal to upgrade the ckBTC minter canister

Git hash: `d1504fc4265703c5c6a73098732a4256ea8ff6bf`

New compressed Wasm hash: `f56526493862ff1fba33d6b4d0350ad5fafdf01c1ab0fc55ac3a53e265aaf392`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/127771

---

## Motivation

This proposal upgrades the ckBTC minter to change the minimum required confirmations for converting BTC into ckBTC from 12 to 6.

There has been no significant code changes affecting the ckBTC minter since the previous upgrade.

## Upgrade args

```
git fetch
git checkout d1504fc4265703c5c6a73098732a4256ea8ff6bf
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant {Upgrade = opt record { min_confirmations = opt 6 }})'
```

## Release Notes

```
git log --format=%C(auto) %h %s 0ce2184ddb42ad0c74aa43ccf4f158d120a5608c..d1504fc4265703c5c6a73098732a4256ea8ff6bf -- rs/bitcoin/ckbtc/minter
73ac384f1 chore(ckbtc): Reduce min_withdrawal_amount to 10_000 for Testnet XC-122
66b0b363c chore: Move async-trait dependency to workspace
f539c0545 chore: Bump rust version to 1.77.1
2ebeecf76 chore: Move assert_matches dependency to workspace
b412b7931 chore: Move `hex` dependency to workspace
0fe5aff1e chore: Move num-traits dependency to workspace
0a0b7504c doc(ckbtc): how to decode memo
1d9d4bc30 chore: bump ic-cdk to 0.12.1
6df0037ce chore(ckBTC): mention ckBTC in minter dashboard page title
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout d1504fc4265703c5c6a73098732a4256ea8ff6bf
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
