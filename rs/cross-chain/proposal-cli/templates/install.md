# Proposal to install the {{canister}} canister

Git hash: `{{at}}`

New compressed Wasm hash: `{{compressed_wasm_hash}}`

Target canister: `{{canister_id}}`

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Install args

```
git fetch
git checkout {{at}}
cd {{canister.repo_dir().as_path().display()}}
{{install_args.didc_encode_cmd()}}
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout {{at}}
./ci/container/build-ic.sh -c
sha256sum ./{{canister.artifact().as_path().display()}}
```
