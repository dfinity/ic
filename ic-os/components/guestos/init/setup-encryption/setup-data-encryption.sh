#!/bin/bash

set -e

if [ -e /dev/sda10 ]; then
    /opt/ic/bin/guest_disk crypt-open store /dev/sda10
    exit 0
fi

echo "- - L" | sfdisk --force --no-reread -a /dev/sda

# Initialize and open encrypted store.
partprobe /dev/sda

/opt/ic/bin/guest_disk crypt-format store /dev/sda10
/opt/ic/bin/guest_disk crypt-open store /dev/sda10
