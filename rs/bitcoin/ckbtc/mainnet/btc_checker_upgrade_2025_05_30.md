# Proposal to upgrade the BTC Checker canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `bb6e758c739768ef6713f9f3be2df47884544900`

New compressed Wasm hash: `a90ed5c89939147cbb58a915343c114787d35835f33609c13be2d802c309b3d9`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `oltsj-fqaaa-aaaar-qal5q-cai`

Previous BTC Checker proposal: https://dashboard.internetcomputer.org/proposal/136101

---

## Motivation

Update the Bitcoin checker canister to include the latest code changes, notably:

* Update the OFAC checklist.
* Avoid caching metrics to have more reliable alerts.

## Release Notes

```
git log --format='%C(auto) %h %s' eecacca6c05871f00e674dcc4bfcf548fa0c2f63..bb6e758c739768ef6713f9f3be2df47884544900 -- rs/bitcoin/checker
9c4e4500ea chore(ckbtc/cketh): update ckBTC/ckETH OFAC blocklists 05.2025 (#5203)
b0a3d6dc4c feat: Add "Cache-Control: no-store" to all canister /metrics endpoints (#5124)
830f4caa90 refactor: remove direct dependency on ic-cdk-macros (#5144)
2949c97ba3 chore: Revert ic-cdk to 0.17.2 (#5139)
d1dc4c2dc8 chore: Update Rust to 1.86.0 (#5059)
3490ef2a07 chore: bump the monorepo version of ic-cdk to 0.18.0 (#5005)
c2d5684360 refactor(ic): update imports from ic_canisters_http_types to newly published ic_http_types crate (#4866)
 ```

## Upgrade args

```
git fetch
git checkout bb6e758c739768ef6713f9f3be2df47884544900
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout bb6e758c739768ef6713f9f3be2df47884544900
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-btc-checker.wasm.gz
```