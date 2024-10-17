#!/bin/bash

# On anything but first boot, machine-id is set up in initramfs and bind-mounted
# over to the rootfs. Since policy is not loaded in initramfs yet, it has
# wrong security context. Fix this up, but ignore failures (this will not
# work on first boot).
restorecon -v /etc/machine-id || true
