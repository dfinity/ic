# Upgrade the Registry Canister to Commit 74bc4ed

__Proposer__: arshavir.ter.gabrielyan at dfinity.org

__Source code__: [74bc4edc43fa7e5315521b91d6e07d073c3c9321][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/74bc4edc43fa7e5315521b91d6e07d073c3c9321

## Summary

* Why are we doing this release?

## New Commits

```
$ git log --format="%C(auto) %h %s" 86229594d61b433c39fc5331ab818ccb6c6aa6a7..74bc4edc43fa7e5315521b91d6e07d073c3c9321 --  ./rs/registry/canister

```


## Current Version

__Current git hash__: 86229594d61b433c39fc5331ab818ccb6c6aa6a7

__Current wasm hash__: b0b2a7f37e76fcbab20a861fdf65c34d7ac2ca84a5190d204dfe5e1c50fb383e


## Verification

See the general instructions on [how to verify] proposals like this. A "quick
start" guide is provided here.

[how to verify]: https://github.com/dfinity/ic/tree/74bc4edc43fa7e5315521b91d6e07d073c3c9321/rs/nervous_system/docs/proposal_verification.md


### WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic/tree/74bc4edc43fa7e5315521b91d6e07d073c3c9321/README.adoc#building-the-code

```
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout 74bc4edc43fa7e5315521b91d6e07d073c3c9321

# 2. Build canisters.
./ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/registry-canister.wasm.gz
```

This should match `wasm_module_hash` field of this proposal.
