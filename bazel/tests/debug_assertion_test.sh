#!/usr/bin/env bash

set -e

if ! "$DEBUG_ASSERTIONS_OFF_BIN"; then
    echo "debug assertions should be off"
    exit 1
fi

if "$DEBUG_ASSERTIONS_ON_BIN"; then
    echo "debug assertions should be on"
    exit 1
fi
