# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `8843e7e6c89aa13efc7caca275d8dd053c11c815`

New compressed Wasm hash: `9125677d7577cd3ceb0ba990615f6a17c9041baf166640fbbc537bb3dfd4f08c`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/134344

---

## Motivation

Upgrade the ckETH minter to add pagination to the developer [dashboard](https://sv3dd-oaaaa-aaaar-qacoa-cai.raw.icp0.io/dashboard).
The current dashboard is too big and can no longer be rendered (`Error from Canister sv3dd-oaaaa-aaaar-qacoa-cai: [...] application payload size (3185081) cannot be larger than 3145728`).

## Upgrade args

```
git fetch
git checkout 8843e7e6c89aa13efc7caca275d8dd053c11c815
cd rs/ethereum/cketh/minter
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9..8843e7e6c89aa13efc7caca275d8dd053c11c815 -- rs/ethereum/cketh/minter
eb61ab2449 refactor(ckbtc/cketh): unify blocklist (#2947)
5368baee2f chore(cketh): add pagination to minter dashboard (#3046)
74f377289b docs(cketh/ckerc20): update docs (#2992)
2456414f7a fix: Use workspace rust edition instead of specifying it in the Cargo.toml file (#3049)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 8843e7e6c89aa13efc7caca275d8dd053c11c815
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
