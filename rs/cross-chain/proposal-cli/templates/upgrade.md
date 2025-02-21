# Proposal to upgrade the {{canister}} canister

Repository: `{{canister.git_repository_url()}}`

Git hash: `{{to}}`

New compressed Wasm hash: `{{compressed_wasm_hash}}`

Upgrade args hash: `{{upgrade_args.args_sha256_hex()}}`

Target canister: `{{canister_id}}`

Previous {{canister}} proposal: {{Self::previous_upgrade_proposal_url(self)}}

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Upgrade args

```
git fetch
git checkout {{to}}
{% if let Some(dir) = canister.repo_dir() -%}
cd {{dir.as_path().display()}}
{% endif -%}
{{upgrade_args.didc_encode_cmd()}} | xxd -r -p | sha256sum
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
{{build_artifact_command}}
sha256sum ./{{canister.artifact().as_path().display()}}
```
