#!/usr/bin/env bash
set -ux

rm -rf results
mkdir -p results

mkdir -p /var/lib/ic/data/benchmark

# Validation of the VM size only, not for merging: the GuestOS VM's memory and vCPUs, and
# dm-crypt's per-device budget for write buffers (2% of memory, split among its devices).
(
    set +x
    grep -E '^MemTotal:' /proc/meminfo
    echo "cpus: $(nproc), vda queues: $(ls /sys/block/vda/mq | wc -l)"
    n=$(dmsetup table | awk '$4 == "crypt"' | wc -l)
    echo "dm-crypt devices: $n, budget per device: $(awk -v n="$n" '/^MemTotal:/ { printf "%.0f MiB", $2 * 0.02 / n / 1024 }' /proc/meminfo)"
) >results/zz-vm.log 2>&1

{ time dd if=/dev/zero of=/var/lib/ic/data/benchmark/out bs=1M count=10000 oflag=direct; } 2>results/big-dd.log
{ time bash -c 'for i in {1..16}; do dd if=/dev/zero of=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 oflag=direct & done ; wait'; } 2>results/small-dds.log
{ time bash -c 'for i in {1..16}; do dd of=/dev/null if=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 iflag=direct & done ; wait'; } 2>results/small-dds-read.log
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=write --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio.log
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=read --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 >results/fio-read.log

./benchmark.sh
# Can hang system, too unreliable to run on nightly CI
# ./stress.sh

exit 0
