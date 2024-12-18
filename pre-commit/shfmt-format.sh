#!/usr/bin/env bash

set -euo pipefail

SHFMT="$(readlink "$shfmt_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

SHFMT_CHECK="${SHFMT_CHECK:-}"

SHFMT_ARGS=(
    --indent 4         # Indent: 0 for tabs (default), >0 for number of spaces.
    --binary-next-line # Binary ops like && and | may start a line.
    --case-indent      # Switch cases will be indented.
)

if [ "$SHFMT_CHECK" == "1" ]; then
    # When checking, error if formatting is needed and print diff
    SHFMT_ARGS+=(--diff)
else
    SHFMT_ARGS+=(--write)
fi

# List all tracked files ending in '.sh' and run formatter
# (note: we use comm to remove files still-tracked but staged for deletion)
if ! comm -23 <(git ls-files | sort) <(git ls-files --deleted | sort) \
    | grep '.sh$' | xargs "$SHFMT" "${SHFMT_ARGS[@]}"; then
    if [ "$SHFMT_CHECK" == "1" ]; then
        cat >&2 <<EOF

[-] Linting Bash script failed
    Please run the following command to fix it:
    $ bazel run //:shfmt-format
EOF
    fi
    exit 1
fi
