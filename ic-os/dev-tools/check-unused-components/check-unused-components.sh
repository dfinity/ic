#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

COMPONENTS_DIR="$REPO_ROOT/ic-os/components"

# ADDITIONAL_USED_COMPONENT_FILES are files used for testing and development
ADDITIONAL_USED_COMPONENT_FILES=(
    "ic-os/components/networking/dev-certs/canister_http_test_ca.key"
    "ic-os/components/networking/dev-certs/root_cert_gen.sh"
)

used_component_files=$(bazel query 'labels(srcs, //ic-os/...)' | sed 's|^//||; s|:|/|')
for file in "${ADDITIONAL_USED_COMPONENT_FILES[@]}"; do
    used_component_files=$(echo -e "$used_component_files\n$file")
done

repo_component_files=$(git -C "$REPO_ROOT" ls-files "$COMPONENTS_DIR")

filtered_repo_component_files=$(echo "$repo_component_files" \
    | grep --invert-match '.adoc$' | grep --invert-match '.md$' | grep --invert-match '.bazel$' | grep --invert-match '.bzl$')

unused_files=$(echo "$filtered_repo_component_files" | grep --invert-match -x -f <(echo "$used_component_files"))

if [ -n "$unused_files" ]; then
    echo "Unused files:"
    echo "$unused_files"
    exit 1
else
    echo "No unused files found."
    exit 0
fi