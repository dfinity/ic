#!/usr/bin/env bash

set -euxo pipefail

# Store output in a temporary file for two reasons:
# * to print the content in the case of an error
# * to automatically catch when ldd or otool exits with a nonzero status
OUT="${TEST_TMPDIR}/ldd.out"

OS="$(uname)"
case "$OS" in
    Darwin)
        otool -L "$@" >"$OUT"
        ;;
    Linux)
        ldd "$@" >"$OUT"
        ;;
    *)
        echo "Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

if grep -qF 'libssl' "$OUT"; then
    echo "OpenSSL dependency found! Binaries can only use standard libraries coming with the opearating system." >&2
    cat "$OUT"
    exit 1
fi
