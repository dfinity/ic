#!/usr/bin/env bash
set -ux

rm -rf results
mkdir -p results

mkdir -p /var/lib/ic/data/benchmark

{ time dd if=/dev/zero of=/var/lib/ic/data/benchmark/out bs=1M count=10000 oflag=direct; } 2>results/big-dd.log
{ time bash -c 'for i in {1..16}; do dd if=/dev/zero of=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 oflag=direct & done ; wait'; } 2>results/small-dds.log
{ time bash -c 'for i in {1..16}; do dd of=/dev/null if=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 iflag=direct & done ; wait'; } 2>results/small-dds-read.log
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=write --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio.log
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=read --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio-read.log

# Replica-like write patterns (bisection branches only, not for merging), 15 s each on the store's
# file system, with dm-crypt's default write path and with `submit_from_crypt_cpus` (set live with
# `cryptsetup refresh`): the deep-queue direct write above; `O_DSYNC` writes from 16 threads (the
# release's flush); `sync_file_range`-paced writes from 4 threads (the candidate's flush); random
# 4 KiB direct reads from 16 threads (execution's page faults), alone and during the paced writes;
# and 32 GB of buffered writes from 4 threads, then `fsync` (a merge's output). Per-layer
# /proc/diskstats for each. Restores the store's flags afterwards.
B=/var/lib/ic/data/benchmark
K=/boot/config/store.keyfile
F=(--norandommap --random_generator=lfsr --group_reporting --percentile_list=50:99:99.9)
# Samples /proc/diskstats of every layer and /proc/stat's CPU line every second into
# results/zz-pat-$1-diskstats.log until /tmp/diag-sampling is removed.
sample() {
    touch /tmp/diag-sampling
    (
        while [ -e /tmp/diag-sampling ]; do
            echo "T $(date +%s.%N)"
            grep -E ' (vd[a-z]+|dm-[0-9]+) ' /proc/diskstats
            grep '^cpu ' /proc/stat
            sleep 1
        done
    ) >results/zz-pat-"$1"-diskstats.log 2>&1 &
}
# Runs fio with arguments $3... as pattern $2 under flag setting $1, printing its bandwidth and
# completion latency lines, then removes its files and empties the page cache.
run() {
    local f=$1 n=$2
    shift 2
    echo "== $f $n"
    sample "$f-$n"
    fio "${F[@]}" "$@" 2>&1 | grep -E 'WRITE: bw=|READ: bw=|^ *(clat percentiles|\| +50\.00th)'
    rm -f /tmp/diag-sampling
    wait
    rm -rf "$B/p"
    sync
    echo 3 >/proc/sys/vm/drop_caches
}
patterns() {
    local f flags w r t0
    echo "store: $(cryptsetup status store-crypt 2>&1 | grep -E 'sector size|flags' | tr -s ' ' | paste -sd' ')"
    w=(--name=w --directory="$B/p" --size=8G --direct=0 --rw=write --ioengine=psync --bs=1m --numjobs=4
        --sync_file_range=wait_before,write:64)
    # Only the first 10 GB of the test file are surely written: elsewhere, reads might find no data.
    r=(--name=r --filename="$B/testfile" --size=10G --direct=1 --rw=randread --ioengine=psync --bs=4k
        --numjobs=16)
    for f in none submit_from_crypt_cpus; do
        flags=(--allow-discards)
        [ "$f" != none ] && flags+=("--perf-$f")
        cryptsetup refresh store-crypt --key-file "$K" "${flags[@]}" >/dev/null 2>&1 || echo "refresh for $f failed"
        echo "=== flags:$(cryptsetup status store-crypt 2>&1 | awk '/flags:/ { $1 = ""; print }')"
        mkdir -p "$B/p"
        run "$f" deep --time_based --runtime=15 --name=deep --filename="$B/testfile" --size=60GB --direct=1 \
            --rw=write --ioengine=libaio --bs=4m --iodepth=32 --numjobs=16
        mkdir -p "$B/p"
        run "$f" dsync16 --time_based --runtime=15 --name=dsync16 --directory="$B/p" --size=4G --direct=0 \
            --sync=dsync --rw=write --ioengine=psync --bs=1m --numjobs=16
        mkdir -p "$B/p"
        run "$f" sfr4 --time_based --runtime=15 "${w[@]}"
        run "$f" reads16 --time_based --runtime=15 "${r[@]}"
        mkdir -p "$B/p"
        run "$f" sfr4-reads16 --time_based --runtime=15 "${w[@]}" "${r[@]}" --new_group
        mkdir -p "$B/p"
        echo "== $f wb4"
        sample "$f-wb4"
        t0=$(date +%s%N)
        fio "${F[@]}" --name=wb4 --directory="$B/p" --size=8G --direct=0 --rw=write --ioengine=psync --bs=1m \
            --numjobs=4 --end_fsync=1 2>&1 | grep -E 'WRITE: bw='
        echo "wb4: 32 GiB written and synced in $((($(date +%s%N) - t0) / 1000000)) ms"
        rm -f /tmp/diag-sampling
        wait
        rm -rf "$B/p"
        sync
        echo 3 >/proc/sys/vm/drop_caches
    done
    cryptsetup refresh store-crypt --key-file "$K" --allow-discards >/dev/null 2>&1 || echo "restoring the store's flags failed"
    echo "store after: $(cryptsetup status store-crypt 2>&1 | grep -E 'flags' | tr -s ' ')"
}
(
    set +x
    patterns
) >results/zz-patterns.log 2>&1

./benchmark.sh
# Can hang system, too unreliable to run on nightly CI
# ./stress.sh

exit 0
