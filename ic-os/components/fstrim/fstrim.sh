#!/bin/bash

# Re-execute the script as root always to allow privileged boot state reporting
# SELinux restrictions and standard permissions still apply, the script and
# the calling user are restricted to being allowed to sudo only this
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

/sbin/fstrim /var/lib/ic/data