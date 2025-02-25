# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `177e28fa4427661462004a738d5ea83329b61f7e`

New compressed Wasm hash: `2a23e5d2aabc5a4f36bb912773ee481209de55b77806f174863f93510abe68ed`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/135282

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Upgrade args

```
git fetch
git checkout 177e28fa4427661462004a738d5ea83329b61f7e
cd rs/bitcoin/ckbtc/minter
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' ddf05d2c70905a99b54c63520b69deef6a4fcc48..177e28fa4427661462004a738d5ea83329b61f7e -- rs/bitcoin/ckbtc/minter
177e28fa44 chore(ckbtc): log get_utxos latency and result size histograms (#3896)
063d442057 fix(ckbtc): Use mempool.space in ckBTC dashboard URLs (#4070)
810eeb14ca chore: use cdk::api::in_replicated_execution (#3949)
6612119c34 chore: Bump ic_cdk version (#3939)
882e7af8e9 chore(crypto): CRP-2697 Move getrandom wasm32-unknown-unknown workaround to packages (#3926)
d18d04b918 fix(ckbtc): use scope guard to prevent double minting (#3930)
5506c7c41e chore: [EXC-1835] Make ic-management-canister-types private (#3814)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 177e28fa4427661462004a738d5ea83329b61f7e
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```