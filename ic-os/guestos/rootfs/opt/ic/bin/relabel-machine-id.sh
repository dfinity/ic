#!/bin/bash

# machine-id is set up in initramfs and bind-mounted over to the rootfs. Since
# policy is not loaded in initramfs yet, it has wrong security context.
restorecon -v /etc/machine-id
