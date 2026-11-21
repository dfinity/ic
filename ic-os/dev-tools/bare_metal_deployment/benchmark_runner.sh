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

# dm-crypt write-path variants on the store (bisection branches only, not for merging): a raw LV in
# the store's volume group, written for 15 s per variant from 16 jobs with 32 requests of 4 MiB in
# flight each, with per-layer /proc/diskstats and a threads view of `top`. The store's flags are
# changed live with `cryptsetup refresh`; `max_write_size` can only lower dm-crypt's 128 KiB
# default. Restores the store's flags and the parameter afterwards.
knobs() {
    local K=/boot/config/store.keyfile C='backup { backup = 0 archive = 0 }' P=/sys/module/dm_crypt/parameters/max_write_size
    local i=0 v sampler flags
    lvcreate --config "$C" --yes -L 64G -n diag store >/dev/null 2>&1 || { echo "no room for the raw LV"; return; }
    echo "store: $(cryptsetup status store-crypt 2>&1 | grep -E 'sector size|flags' | tr -s ' ' | paste -sd' ')"
    for v in baseline submit_from_crypt_cpus no_write_workqueue same_cpu_crypt max_write_size_64k baseline; do
        i=$((i + 1))
        flags=(--allow-discards)
        case $v in submit_from_crypt_cpus | no_write_workqueue | same_cpu_crypt) flags+=("--perf-$v") ;; esac
        cryptsetup refresh store-crypt --key-file "$K" "${flags[@]}" >/dev/null 2>&1 || echo "refresh for $v failed"
        [ "$v" = max_write_size_64k ] && echo 65536 >"$P"
        echo "== $i $v (flags:$(cryptsetup status store-crypt 2>&1 | awk '/flags:/ { $1 = ""; print }'), max_write_size $(cat "$P"))"
        touch /tmp/diag-sampling
        (
            while [ -e /tmp/diag-sampling ]; do
                echo "T $(date +%s.%N)"
                grep -E ' (vd[a-z]+|dm-[0-9]+) ' /proc/diskstats
                grep '^cpu ' /proc/stat
                sleep 1
            done
        ) >"results/zz-knob-$i-$v-diskstats.log" 2>&1 &
        sampler=$!
        (sleep 5 && top -b -H -n 2 -d 5 -w 160 -o %CPU | awk '/^top -/ { n++ } n == 2' | head -20) >"results/zz-knob-$i-$v-top.log" 2>&1 &
        fio --direct=1 --buffered=0 --norandommap --random_generator=lfsr --rw=write --ioengine=libaio \
            --group_reporting --time_based --runtime=15 --name="$v" --filename=/dev/store/diag --size=64G \
            --numjobs=16 --iodepth=32 --bs=4m 2>&1 | grep -E 'WRITE: bw=|^ +clat \('
        rm -f /tmp/diag-sampling
        wait "$sampler"
        wait
        echo 0 >"$P"
    done
    cryptsetup refresh store-crypt --key-file "$K" --allow-discards >/dev/null 2>&1 || echo "restoring the store's flags failed"
    echo "store after: $(cryptsetup status store-crypt 2>&1 | grep -E 'flags' | tr -s ' ')"
    lvremove --config "$C" -f store/diag >/dev/null 2>&1
}
(
    set +x
    knobs
) >results/zz-knobs.log 2>&1

./benchmark.sh
# Can hang system, too unreliable to run on nightly CI
# ./stress.sh

exit 0
