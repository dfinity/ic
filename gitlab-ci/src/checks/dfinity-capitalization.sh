#!/usr/bin/env bash

# This script added to invert grep semantics.
if grep -I -n -P "\bDfinity\b" "$@"; then
    exit 1
fi
