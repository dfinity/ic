# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `c016162d2861e5ad6260d4f62c511a3e5cef5a31`

New compressed Wasm hash: `96e98bbddf63f1b381f1a36801f3e9d93336b0023823b4d33d38fead41103fa1`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/140090

---

## Motivation

Regular upgrade of the ckBTC minter to the latest version.


## Release Notes

```
git log --format='%C(auto) %h %s' b2d93fe83a8f878a331d73df1cffed72022860b2..c016162d2861e5ad6260d4f62c511a3e5cef5a31 -- rs/bitcoin/ckbtc/minter
79cbc4b37c fix(ckbtc): compute minter str address in retrieve_btc (#8671)
990e96bf57 fix(ckbtc/ckdoge): defuse guard directly after signing transaction (#8579)
 ```

## Upgrade args

```
git fetch
git checkout c016162d2861e5ad6260d4f62c511a3e5cef5a31
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c016162d2861e5ad6260d4f62c511a3e5cef5a31
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
