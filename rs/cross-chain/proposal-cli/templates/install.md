# Proposal to install the {{canister}} canister

Repository: `{{canister.git_repository_url()}}`

Git hash: `{{at}}`

New compressed Wasm hash: `{{compressed_wasm_hash}}`

Install args hash: `{{install_args.args_sha256_hex()}}`

Target canister: `{{canister_id}}`

{% if !canister.forum_discussion().is_empty() -%}
Forum discussion: {{canister.forum_discussion()}}

{% endif -%}
---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Install args

```
git fetch
git checkout {{at}}
{{install_args.didc_encode_cmd()}} | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout {{at}}
{{build_artifact_command}}
sha256sum ./{{canister.artifact().as_path().display()}}
```
