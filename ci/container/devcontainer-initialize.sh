#!/usr/bin/env bash
# Runs on the host as the initializeCommand of .devcontainer/devcontainer.json,
# before the VS Code dev container is created and again on every start.
#
# Usage: devcontainer-initialize.sh <local workspace folder> <devcontainer id>
set -eEuo pipefail

WORKSPACE="${1:?usage: $0 <local workspace folder> <devcontainer id>}"
DEVCONTAINER_ID="${2:?usage: $0 <local workspace folder> <devcontainer id>}"

# The directories and files that devcontainer.json bind-mounts must exist.
mkdir -p ~/.aws ~/.ssh ~/.cache/cargo ~/.claude ~/.local/share/fish /tmp/ict_testnets
touch ~/.zsh_history ~/.bash_history

# Give the dev container of this checkout its own bazel output base (see the
# explanation in container-run.sh). The rc file lives under ~/.cache, which
# devcontainer.json mounts at /home/ubuntu/.cache, and its containerEnv points
# BAZELRC at the container-side path of this same file. The file is named after
# ${devcontainerId} (a stable, per-checkout base32 hash substituted by the Dev
# Container tooling in both places) rather than after the checkout path, because
# $BAZELRC is a comma-separated list and must not contain arbitrary path
# characters.
#
# The key gets a "devcontainer-" prefix so that a VS Code dev container and a
# container-run.sh container of the same checkout never share an output base:
# they run in separate PID namespaces, so bazel invocations from one (e.g. the
# Bazel extension's background queries) would kill the server of the other.
OUTPUT_BASE_KEY="devcontainer-$("$WORKSPACE"/ci/container/bazel-output-base-key.sh "$WORKSPACE")"
BAZELRC_FILE="$HOME/.cache/container-run/devcontainer-$DEVCONTAINER_ID.bazelrc"
mkdir -p "$(dirname "$BAZELRC_FILE")"
echo "startup --output_base=/home/ubuntu/.cache/bazel/_bazel_ubuntu/$OUTPUT_BASE_KEY" >"$BAZELRC_FILE"
