#!/bin/sh

ic-admin \
    propose-to-change-nns-canister \
    --canister-id {{canister_id}} \
    --mode {{mode}} \
    --wasm-module-path "{{wasm_module_path}}" \
    --wasm-module-sha256 {{wasm_module_sha256}} \
    --arg "{{arg}}" \
    --summary-file "{{summary_file}}"


