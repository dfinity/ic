#!/usr/bin/env bash
set -ux

rm -rf results
mkdir -p results

mkdir -p /var/lib/ic/data/benchmark

# Diagnostics for the deep-queue write collapse with 4 KiB encryption sectors (bisection branches
# only, not for merging). The VM: memory, CPUs, cache domains, workqueue scope, dm-crypt devices
# and the per-device budget for encrypted write buffers (2% of memory, split among them).
(
    set +x
    grep -E '^(MemTotal|MemFree|Cached):' /proc/meminfo
    echo "cpus: $(nproc)"
    echo "L3 domains: $(cat /sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list 2>/dev/null | sort -u | paste -sd' ')"
    echo "workqueue scope: $(cat /sys/module/workqueue/parameters/default_affinity_scope)"
    n=$(dmsetup table | awk '$4 == "crypt"' | wc -l)
    echo "dm-crypt devices: $n, budget per device: $(awk -v n="$n" '/^MemTotal:/ { printf "%.0f MiB", $2 * 0.02 / n / 1024 }' /proc/meminfo)"
    echo "vda queues: $(ls /sys/block/vda/mq | wc -l)"
    for f in nr_requests max_sectors_kb max_segments rq_affinity nomerges; do
        echo "vda $f=$(cat /sys/block/vda/queue/$f)"
    done
    cryptsetup status store-crypt 2>&1 | grep -E 'sector size|flags' | tr -s ' '
    grep -E 'virtio[0-9]+-(req|request)' /proc/interrupts | awk '{ print $1, $NF }' | paste -sd' '
) >results/zz-d2-env.log 2>&1

{ time dd if=/dev/zero of=/var/lib/ic/data/benchmark/out bs=1M count=10000 oflag=direct; } 2>results/big-dd.log
{ time bash -c 'for i in {1..16}; do dd if=/dev/zero of=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 oflag=direct & done ; wait'; } 2>results/small-dds.log
{ time bash -c 'for i in {1..16}; do dd of=/dev/null if=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 iflag=direct & done ; wait'; } 2>results/small-dds-read.log

# Samples every second, until /tmp/diag-sampling is removed, into results/zz-d2-$1-samples.log
# (headed `== $1`): the time; /proc/diskstats of every layer; every CPU's /proc/stat line;
# /proc/buddyinfo's Normal zones; and for the store's dm-crypt workers and write thread, one
# `P <pid> <state> <cpu> <name>` line each, followed by the top of the kernel stack when blocked
# (state D). Also snapshots /proc/interrupts, /proc/softirqs and /proc/vmstat before and after,
# into results/zz-d2-$1-{before,after}.log.
sample() {
    {
        cat /proc/interrupts /proc/softirqs
        grep -E '^(allocstall|compact_|pgscan|pgsteal|pgalloc|kswapd|pageoutrun|nr_free_pages )' /proc/vmstat
    } >results/zz-d2-"$1"-before.log 2>&1
    touch /tmp/diag-sampling
    (
        set +x
        echo "== $1"
        while [ -e /tmp/diag-sampling ]; do
            echo "T $(date +%s.%N)"
            grep -E ' (vd[a-z]+|dm-[0-9]+) ' /proc/diskstats
            grep '^cpu' /proc/stat
            grep Normal /proc/buddyinfo
            for d in /proc/[0-9]*; do
                { read -r c <"$d/comm"; } 2>/dev/null || continue
                case $c in
                    *kcryptd-* | dmcrypt_write*) ;;
                    *) continue ;;
                esac
                { read -r -a st <"$d/stat"; } 2>/dev/null || continue
                echo "P ${d#/proc/} ${st[2]} ${st[38]} $c"
                if [ "${st[2]}" = D ]; then
                    echo "  $(sed 's/^\[<[0-9a-f]*>\] //; s/+0x.*//' "$d/stack" 2>/dev/null | head -8 | paste -sd'<')"
                fi
            done
            sleep 1
        done
    ) >results/zz-d2-"$1"-samples.log 2>&1 &
}
# Stops sample $1's sampler and takes its `after` snapshots.
unsample() {
    rm -f /tmp/diag-sampling
    wait
    {
        cat /proc/interrupts /proc/softirqs
        grep -E '^(allocstall|compact_|pgscan|pgsteal|pgalloc|kswapd|pageoutrun|nr_free_pages )' /proc/vmstat
    } >results/zz-d2-"$1"-after.log 2>&1
}

sample write
(set +x && sleep 10 && top -b -H -n 2 -d 5 -w 160 -o %CPU | awk '/^top -/ { n++ } n == 2' | head -45) >results/zz-d2-write-top.log 2>&1 &
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=write --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio.log
unsample write
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=read --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio-read.log

# Overwrites of the test file for 20 s each by 16 jobs of 4 MiB writes, 2 to 32 in flight per job
# (128 MiB to 2 GiB in all), with dm-crypt's default write path, then 32 in flight with
# `submit_from_crypt_cpus` (set live with `cryptsetup refresh`), each sampled as above: whether the
# collapse starts where the data in flight exceeds dm-crypt's buffer budget. Restores the store's
# flags afterwards.
(
    set +x
    K=/boot/config/store.keyfile
    T=(--filename=/var/lib/ic/data/benchmark/testfile --size=60GB --direct=1 --buffered=0 --norandommap
        --random_generator=lfsr --rw=write --ioengine=libaio --group_reporting --time_based --runtime=20
        --numjobs=16 --bs=4m)
    for v in none-d2 none-d4 none-d8 none-d16 none-d32 sfcc-d32; do
        flags=(--allow-discards)
        case $v in sfcc-*) flags+=(--perf-submit_from_crypt_cpus) ;; esac
        cryptsetup refresh store-crypt --key-file "$K" "${flags[@]}" >/dev/null 2>&1 || echo "refresh for $v failed"
        echo "== $v (flags:$(cryptsetup status store-crypt 2>&1 | awk '/flags:/ { $1 = ""; print }'))"
        sample "$v"
        fio "${T[@]}" --name="$v" --iodepth="${v##*-d}" 2>&1 | grep -E 'WRITE: bw='
        unsample "$v"
    done
    cryptsetup refresh store-crypt --key-file "$K" --allow-discards >/dev/null 2>&1 || echo "restoring the store's flags failed"
    echo "store after: $(cryptsetup status store-crypt 2>&1 | grep -E 'flags' | tr -s ' ')"
) >results/zz-d2-overwrite.log 2>&1

./benchmark.sh
# Can hang system, too unreliable to run on nightly CI
# ./stress.sh

exit 0
