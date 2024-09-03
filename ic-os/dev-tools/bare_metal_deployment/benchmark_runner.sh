#!/usr/bin/env bash
set -ux

rm -rf results
mkdir -p results

mkdir -p /var/lib/ic/data/bencmark

{ time dd if=/dev/zero of=/var/lib/ic/data/benchmark/out bs=1M count=10000 oflag=direct ; } 2> results/big-dd.log
{ time bash -c 'for i in {1..16}; do dd if=/dev/zero of=/var/lib/ic/data/benchmark/out_${i} bs=1M count=1000 oflag=direct & done ; wait' ; } 2> results/small-dds.log
fio --filename=/var/lib/ic/data/benchmark/testfile --io_size=10GB --size=60GB --direct=1 --buffered=0 --invalidate 1 --norandommap --random_generator=lfsr --rw=write --bs=4m --ioengine=libaio --iodepth=32 --numjobs=16 --group_reporting --name=throughput-sw-job --eta-newline=1 > results/fio.log

./benchmark.sh
./stress.sh

exit 0
