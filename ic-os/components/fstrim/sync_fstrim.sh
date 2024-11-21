#!/bin/bash
set -e

# Re-execute the script as root always to allow privileged boot state reporting
# SELinux restrictions and standard permissions still apply, the script and
# the calling user are restricted to being allowed to sudo only this
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

PATH=/var/lib/ic/data

echo "Executing sync on $PATH"
sync --file-system $PATH

echo "Executing fstrim on $PATH"
/sbin/fstrim $PATH

echo "Finished sync & fstrim"
