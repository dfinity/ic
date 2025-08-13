# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `47c5931cdafd82167feee85faf1e1dffa30fc3d8`

New compressed Wasm hash: `2c3aa7ce48ab9412a9189fea4758c8e4630fda4cc429ebf1a52b9aa09c5f5dbd`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/136598

---

## Motivation

Upgrade the ckBTC minter to ensure that a transaction signed by the minter does not use too many inputs.
Otherwise, the resulting transaction may be *non-standard* as the resulting transaction size may be above 100kB,
which implies that the transaction will not be relayed by Bitcoin nodes and this transaction will be effectively stuck.
This is currently the case for transaction `87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30`.

This is a stop-gap solution until a proper solution is implemented.

## Release Notes

```
git log --format='%C(auto) %h %s' f8131bfbc2d339716a9cff06e04de49a68e5a80b..47c5931cdafd82167feee85faf1e1dffa30fc3d8 -- rs/bitcoin/ckbtc/minter
47c5931cda fix(ckbtc): Ensure minimum fee per vbyte (#5742)
db7850caa4 fix(ckbtc): fix a bug in resubmitting stuck transactions (#5713)
b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
d1dc4c2dc8 chore: Update Rust to 1.86.0 (#5059)
3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
a86da36995 refactor(cross-chain): use public crate ic-management-canister-types (#4903)
ccb066b19e chore(ckbtc): update README (#2956)
c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
 ```

## Upgrade args

```
git fetch
git checkout 47c5931cdafd82167feee85faf1e1dffa30fc3d8
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 47c5931cdafd82167feee85faf1e1dffa30fc3d8
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
