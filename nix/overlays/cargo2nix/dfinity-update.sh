#!/usr/bin/env bash
set -e

echo "nix-build ./release.nix"
out_path="$(nix-build "$(dirname "$0")/release.nix" --no-out-link)"
echo " => $out_path"

echo "uploading to s3"
aws s3 cp "$out_path/bin/cargo2nix" s3://dfinity-download-public/tools/cargo2nix
echo "done"
