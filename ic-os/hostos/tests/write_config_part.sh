#!/usr/bin/env bash

# Write image to config LVM of hostos image
#
# Arguments:
#   $1: The disk image to be read from.
#   $2: The disk image to write to.

set -eo pipefail

# -----------------------------------------------------------------------

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..

source ${BASE_DIR}/../scripts/partitions.sh ${BASE_DIR}

write_single_lvm_volume $2 hostlvm config $1
