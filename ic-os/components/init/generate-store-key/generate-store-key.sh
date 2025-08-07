#!/bin/bash

# Generate a random key for the encrypted store.

set -eo pipefail

umask 0077
# Instead of writing to store.keyfile directly, we use a temporary file to
# avoid overwriting store.keyfile because of a race condition (e.g., if
# two processes try to create store.keyfile or if /boot/config gets mounted
# between the time we check the existence and write to the file).
if [ ! -f /boot/config/store.keyfile ]; then
    TMPFILE="$(mktemp --tmpdir=/boot/config)"
    dd if=/dev/random of="$TMPFILE" bs=16 count=1
    mv -n "$TMPFILE" /boot/config/store.keyfile
    sync
fi
