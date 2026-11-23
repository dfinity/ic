#!/bin/bash

# Accepts all of a TEE (SEV-SNP) guest's memory in the background after boot.
#
# SEV-SNP memory must be accepted before use, and the kernel accepts it lazily: unaccepted memory
# counts as free, and more is accepted only when free memory runs low, not when it is too fragmented
# for an allocation, which then reclaims page cache instead. `accept_memory=eager` accepts it all
# before the kernel even brings up its console, which takes over 14 minutes for a 480 GiB guest.
# Filling a tmpfs makes the kernel accept the memory that fills it; the tmpfs is this service's
# own, so its memory is freed when the service exits. Acceptance runs at 1-1.5 GiB/s however many
# vCPUs do it (the host serializes it), and many starve the rest of the guest, so a few do it.
#
# Usage: accept-memory.sh <directory on an empty tmpfs>

set -euo pipefail

dir=$1

# Prints the unaccepted memory in KiB (0 if the kernel reports none).
unaccepted_kib() {
    local key value rest
    while read -r key value rest; do
        if [ "${key}" = "Unaccepted:" ]; then
            echo "${value}"
            return
        fi
    done </proc/meminfo
    echo 0
}

# Extends file $1 in steps of $2 MiB while more than $3 KiB of memory is unaccepted.
fill() {
    local offset=0
    while [ "$(unaccepted_kib)" -gt "$3" ]; do
        fallocate --offset "$((offset << 20))" --length "$(($2 << 20))" "$1" || return 0
        offset=$((offset + $2))
    done
}

# Logs, with the seconds since boot.
log() {
    local uptime rest
    read -r uptime rest </proc/uptime
    echo "accept-memory: ${uptime} s after boot: $*"
}

# Runs $1 fills in parallel, in steps of $2 MiB, until at most $3 MiB more than their last steps stay
# unaccepted, so that those steps can't take accepted memory instead.
fill_parallel() {
    local stop=$((($1 * $2 + $3) << 10)) i
    for i in $(seq "$1"); do
        fill "${dir}/$2-${i}" "$2" "${stop}" &
    done
    wait
}

start=$(unaccepted_kib)
log "$((start >> 20)) GiB unaccepted"
fill_parallel 4 256 1024
fill_parallel 1 64 256
rm -f "${dir}"/*
log "accepted $(((start - $(unaccepted_kib)) >> 20)) GiB in ${SECONDS} s, $(($(unaccepted_kib) >> 10)) MiB left"
