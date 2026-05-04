#!/usr/bin/env bash

set -euo pipefail

file_size=$(wc -c <"$FILE")

if [ "$file_size" -gt "$MAX_SIZE" ]; then
    echo "'$FILE', '$file_size' bytes exceeds the allowed maximum size '$MAX_SIZE'" >&2
    exit 1
else
    echo "'$FILE', '$file_size' bytes is below the allowed maximum size '$MAX_SIZE'"
fi
