#!/usr/bin/env bash
set -eEou pipefail

CREATE_UNIVERSAL_VM_CONFIG_IMAGE="$1"
INPUT_TAR="$2"
OUTPUT_IMG="$3"

tmpdir="$(mktemp -d)"

tar -xf "$INPUT_TAR" -C "$tmpdir"

"$CREATE_UNIVERSAL_VM_CONFIG_IMAGE" --input "$tmpdir" --output "$OUTPUT_IMG" --label CONFIG
