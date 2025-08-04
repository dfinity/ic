#!/bin/bash

set -e

if [ -e /dev/vda10 ]; then
    /opt/ic/bin/guest_disk crypt-open store /dev/vda10
    exit 0
fi

echo "- - L" | sfdisk --force --no-reread -a /dev/vda

# Generate a key and initialize encrypted store with it.
partprobe /dev/vda
umask 0077

/opt/ic/bin/guest_disk crypt-format store /dev/vda10
/opt/ic/bin/guest_disk crypt-open store /dev/vda10
