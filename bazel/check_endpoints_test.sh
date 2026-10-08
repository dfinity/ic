#!/usr/bin/env bash
set -euo pipefail
exec "$IC_WASM" "$WASM" check-endpoints --hidden "$HIDDEN"
