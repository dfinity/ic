# Proposal to upgrade the {{canister}} canister

Git hash: `{{to}}`

New compressed Wasm hash: `{{compressed_wasm_hash}}`

Target canister: `{{canister_id}}`

Previous {{canister}} proposal: {{Self::previous_upgrade_proposal_url(self)}}

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Upgrade args

```
git fetch
git checkout {{to}}
cd {{canister.repo_dir().as_path().display()}}
{{upgrade_args.didc_encode_cmd()}}
```

## Release Notes

```
{{release_notes}}
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout {{to}}
./ci/container/build-ic.sh -c
sha256sum ./{{canister.artifact().as_path().display()}}
```
