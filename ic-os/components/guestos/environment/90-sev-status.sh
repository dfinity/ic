#!/bin/bash

# Set TEE_ENABLED environment variable based on kernel command line.
if grep -qE "(^|[[:space:]])dfinity\.tee(=|[[:space:]]|$)" /proc/cmdline; then
    echo "TEE_ENABLED=1"
else
    echo "TEE_ENABLED=0"
fi
