#!/bin/bash
set -eu
TEMPFILE=$(mktemp)

# The version of `json5` available on CI containers does not support
# the `--validate` argument so we have to copy to a temporary file
# and compile in place with the `-c` argument to check validity.
sed <"${1?missing json5 file}" 's/{{[^}]*}}/0/g' >"$TEMPFILE"

echo "Validating: $1"
json5 -c "$TEMPFILE"
