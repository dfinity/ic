#!/usr/bin/env bash

# This script added to invert grep semantics.
if grep -I -i -n -E "DO[^\w]?NOT[^\w]?MERGE" "$@"; then
    exit 1
fi
