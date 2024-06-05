#!/bin/bash

if ! command -v stress-ng &>/dev/null; then
    echo "stress-ng not found. Run 'sudo apt install stress-ng'"
    exit 1
fi

set -u
set -x

# Exercise all stressors sequentially. Use all processors.
# Time out after 10 seconds for each stressor.
# Print metrics. Verify outputs where relevant.
# Note that using the `--all` parameter instead of `--sequential` may crash the machine.
stress-ng --sequential "$(nproc)" \
    --log-file "./stress_test_$(hostname)_$(date +%Y-%m-%dT%H-%M-%S).txt" \
    --timeout 30 \
    --metrics \
    --verify \
    --times \
    --exclude chattr || {
    echo "Failed. Check logs"
    exit 1
}
