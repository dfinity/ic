#!/usr/bin/env bash
#
# Convenience tail for the 4 replica containers, with an optional grep
# filter applied across all nodes' interleaved log streams.
#
# Examples:
#   ./logs.sh                       # tail everything
#   ./logs.sh consensus             # only lines mentioning "consensus"
#   ./logs.sh -E "ERRO|FATAL|panic" # all error-ish lines
#   ./logs.sh --since 1m            # last minute only, no filter
#
# Anything after the first `--`, or that starts with `-`, is forwarded to
# `docker compose logs`. Everything else is treated as a grep pattern.
set -euo pipefail

LOCAL_NET_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LOCAL_NET_DIR"

LOGS_ARGS=()
GREP_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --)
            shift
            LOGS_ARGS+=("$@")
            break
            ;;
        -*)
            LOGS_ARGS+=("$1")
            shift
            ;;
        *)
            GREP_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ${#GREP_ARGS[@]} -eq 0 ]; then
    exec docker compose logs -f --tail=20 "${LOGS_ARGS[@]}"
else
    exec docker compose logs -f --tail=200 "${LOGS_ARGS[@]}" \
        | grep --line-buffered -E "${GREP_ARGS[@]}"
fi
