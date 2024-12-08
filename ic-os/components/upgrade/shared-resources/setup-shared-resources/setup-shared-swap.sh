#!/bin/bash

set -e

blkid /dev/mapper/store-shared--swap >/dev/null || (
    mkswap /dev/mapper/store-shared--swap
)
