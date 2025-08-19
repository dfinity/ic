# Proposal to upgrade the {{canister}} canister

Repository: `{{canister.git_repository_url()}}`

Git hash: `{{to}}`

New compressed Wasm hash: `{{compressed_wasm_hash}}`

Upgrade args hash: `{{upgrade_args.args_sha256_hex()}}`

Target canister: `{{canister_id}}`

Previous {{canister}} proposal: {{Self::previous_upgrade_proposal_url(self)}}

{% if !canister.forum_discussion().is_empty() -%}
Forum discussion: {{canister.forum_discussion()}}

{% endif -%}
---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Release Notes

```
{{release_notes}}
 ```

## Upgrade args

```
git fetch
git checkout {{to}}
{{upgrade_args.didc_encode_cmd()}} | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout {{to}}
{{build_artifact_command}}
sha256sum ./{{canister.artifact().as_path().display()}}
```
