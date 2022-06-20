#!/bin/bash

set -e

blkid /dev/mapper/store-nginx--cache >/dev/null || (
    mkfs.ext4 /dev/mapper/store-nginx--cache -d /var/cache/nginx
)
