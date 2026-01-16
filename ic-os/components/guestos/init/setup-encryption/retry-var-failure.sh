#!/bin/bash

# If it is detected that var failed to properly mount, write a metric, wait for
# it to send, and trigger a reboot to get out of the situation.
#
# For context, a race between fsck and udev has been seen to lock up the var
# mount. After the fsck has been performed, a reboot (or even a remount) will
# bring GuestOS back into shape.

source /opt/ic/bin/metrics.sh

write_metric "tainted_var" \
    "1" \
    "Var is tainted on startup" \
    "gauge"

sleep 2

systemctl reboot

sleep 15

systemctl reboot --force
