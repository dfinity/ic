#!/bin/bash

# Accepts all of a TEE (SEV-SNP) guest's memory right after boot, from all vCPUs at once.
#
# SEV-SNP memory must be accepted before use, and the kernel accepts it lazily: unaccepted memory
# counts as free, and more is accepted only when free memory runs low, not when it is too fragmented
# for an allocation, which then reclaims page cache instead. `accept_memory=eager` accepts it all at
# boot, but on one CPU, which takes over 14 minutes for a 480 GiB guest. Filling a tmpfs from every
# vCPU makes the kernel accept it in parallel; the tmpfs is this service's own, so its memory is
# freed when the service exits.
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

# Logs to the kernel log, whose timestamps show the boot time this takes.
log() {
    echo "accept-memory: $*"
    echo "accept-memory: $*" 2>/dev/null >/dev/kmsg || true
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
fill_parallel "$(nproc)" 256 1024
fill_parallel 8 64 256
fill_parallel 1 16 64
rm -f "${dir}"/*
log "accepted $(((start - $(unaccepted_kib)) >> 20)) GiB in ${SECONDS} s, $(($(unaccepted_kib) >> 10)) MiB left"
