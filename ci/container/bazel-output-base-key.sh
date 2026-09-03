#!/usr/bin/env bash
# Prints the key that identifies the bazel output base of a checkout: the
# checkout's basename, reduced to [A-Za-z0-9._-] and at most 64 characters so
# that it is safe in a bazelrc line, in the comma-separated $BAZELRC variable
# and in a file name, followed by the first 8 hex digits of the sha256 of the
# checkout's host path, which keeps the key unique.
#
# Shared by container-run.sh and devcontainer-initialize.sh so that both
# container flavours derive their output bases the same way.
#
# Usage: bazel-output-base-key.sh <checkout path>
set -eEuo pipefail

REPO_ROOT="${1:?usage: $0 <checkout path>}"

REPO_NAME="$(printf '%s' "$(basename "$REPO_ROOT")" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)"
echo "$REPO_NAME-$(printf '%s' "$REPO_ROOT" | sha256sum | cut -c1-8)"
