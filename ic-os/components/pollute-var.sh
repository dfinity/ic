#!/bin/bash

debugfs -w -R "ssv free_blocks_count 89999" /dev/mapper/var_crypt

# dd if=/dev/urandom of=/dev/mapper/var_crypt bs=4K count=1 seek=1 conv=notrunc

# while true; do
#     yes | dd of=/var/trash bs=512B count=10000000 oflag=direct
# done

# yes > /var/trash &

# while true; do
#     sleep 5
#     truncate -s 0 /var/trash
# done
