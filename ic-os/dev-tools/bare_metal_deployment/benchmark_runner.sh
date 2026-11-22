#!/usr/bin/env bash
set -ux

rm -rf results
mkdir -p results

mkdir -p /var/lib/ic/data/benchmark

# Diagnostics for the deep-queue write drop with 4 KiB encryption sectors (bisection branches
# only, not for merging): the disk stack's limits and layout; per-second /proc/diskstats of every
# layer and a threads view of `top` during the `fio` write; and a short write sweep afterwards.
# Each in a subshell without the trace.
(
    set +x
    uname -a
    echo "store: $(cryptsetup status store-crypt 2>&1 | grep -E 'sector size|flags' | tr -s ' ' | paste -sd' ')"
    lsblk -o NAME,KNAME,SIZE,TYPE,LOG-SEC,PHY-SEC,MIN-IO,OPT-IO,DISC-GRAN,MOUNTPOINT
    for d in /sys/block/vd* /sys/block/dm-*; do
        echo "== ${d##*/} ($(cat "$d/dm/name" 2>/dev/null))"
        for f in logical_block_size physical_block_size max_sectors_kb max_hw_sectors_kb max_segments \
            max_segment_size nr_requests minimum_io_size optimal_io_size scheduler nomerges rotational \
            write_cache fua; do
            echo "$f=$(cat "$d/queue/$f" 2>/dev/null)"
        done
    done
    echo "vda queues: $(ls /sys/block/vda/mq | wc -l)"
    for v in /sys/bus/virtio/devices/*; do echo "${v##*/} $(cat "$v/device") $(cat "$v/features")"; done
    # The crypt targets' key fields replaced.
    dmsetup table | awk '$4 == "crypt" { $6 = "<key>" } { print }'
    vgs --config 'backup { backup = 0 archive = 0 }' 2>&1
    lvs --config 'backup { backup = 0 archive = 0 }' 2>&1
    xfs_info /var/lib/ic/data
    findmnt -o TARGET,SOURCE,OPTIONS /var/lib/ic/data
) >results/zz-diag-env.log 2>&1

{ time dd if=/dev/zero of=/var/lib/ic/data/benchmark/out bs=1M count=10000 oflag=direct; } 2>results/big-dd.log
{ time bash -c 'for i in {1..16}; do dd if=/dev/zero of=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 oflag=direct & done ; wait'; } 2>results/small-dds.log
{ time bash -c 'for i in {1..16}; do dd of=/dev/null if=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 iflag=direct & done ; wait'; } 2>results/small-dds-read.log

# Samples /proc/diskstats of every layer and /proc/stat's CPU line every second into
# results/zz-diag-diskstats-$1.log (headed `== $1`) until /tmp/diag-sampling is removed.
sample() {
    touch /tmp/diag-sampling
    (
        set +x
        echo "== $1"
        while [ -e /tmp/diag-sampling ]; do
            echo "T $(date +%s.%N)"
            grep -E ' (vd[a-z]+|dm-[0-9]+) ' /proc/diskstats
            grep '^cpu ' /proc/stat
            sleep 1
        done
    ) >results/zz-diag-diskstats-"$1".log 2>&1 &
}
sample write
(set +x && sleep 10 && top -b -H -n 2 -d 5 -w 160 -o %CPU | awk '/^top -/ { n++ } n == 2' | head -45) >results/zz-diag-top-write.log 2>&1 &
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=write --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio.log
rm -f /tmp/diag-sampling
wait
sample read
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=read --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio-read.log
rm -f /tmp/diag-sampling
wait
# Whether the read right after the write is slowed by the drives still absorbing that write: the
# same read again after 2 minutes idle.
sleep 120
sample read2
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=read --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job2 >results/zz-diag-fio-read2.log
rm -f /tmp/diag-sampling
wait

# Write sweep, 15 s per point: overwriting the 60 GB test file in place (no allocation), then new
# files per job (allocating and extending, as the first write of the test file does), then a raw
# LV in the store's volume group (no file system).
sweep() {
    echo "== $1"
    fio --direct=1 --buffered=0 --norandommap --random_generator=lfsr --rw=write --ioengine=libaio \
        --group_reporting --time_based --runtime=15 --name="$1" "${@:2}" 2>&1 |
        grep -E 'WRITE: bw=|^ +(clat|lat) \(|^ +cpu +:'
}
(
    set +x
    T=(--filename=/var/lib/ic/data/benchmark/testfile --size=60GB)
    sweep overwrite-j16-d32-4m "${T[@]}" --numjobs=16 --iodepth=32 --bs=4m
    sweep overwrite-j16-d4-4m "${T[@]}" --numjobs=16 --iodepth=4 --bs=4m
    sweep overwrite-j16-d1-4m "${T[@]}" --numjobs=16 --iodepth=1 --bs=4m
    sweep overwrite-j16-d32-1m "${T[@]}" --numjobs=16 --iodepth=32 --bs=1m
    sweep overwrite-j1-d32-4m "${T[@]}" --numjobs=1 --iodepth=32 --bs=4m
    mkdir -p /var/lib/ic/data/benchmark/sweep
    # 8 GB per job, for 8 s: the first, allocating pass even at 15 GB/s.
    sweep newfiles-j16-d32-4m --directory=/var/lib/ic/data/benchmark/sweep --size=8GB --runtime=8 --numjobs=16 --iodepth=32 --bs=4m
    rm -rf /var/lib/ic/data/benchmark/sweep
    C='backup { backup = 0 archive = 0 }'
    if lvcreate --config "$C" --yes -L 64G -n diag store >/dev/null 2>&1; then
        sweep rawlv-j16-d32-4m --filename=/dev/store/diag --size=64G --numjobs=16 --iodepth=32 --bs=4m
        lvremove --config "$C" -f store/diag >/dev/null 2>&1
    else
        echo "== rawlv: no room for a 64 GiB LV in VG store"
    fi
) >results/zz-diag-sweep.log 2>&1
dmesg -T 2>&1 | grep -i -E 'xfs|dm-|crypt|virtio|blk|nvme|i/o error' | tail -40 >results/zz-diag-dmesg.log

./benchmark.sh
# Can hang system, too unreliable to run on nightly CI
# ./stress.sh

exit 0
