#!/bin/bash

graceful_exit() {
    echo "Failed. Check logs for more info"
    exit 1
}

print_exec() {
    echo "Running: $@"
    "$@" || graceful_exit
}

if ! command -v sysbench &>/dev/null; then
    echo "sysbench not found. Run 'sudo apt install sysbench'"
    exit
fi

TMP_DIR_FS=$(stat -f -c %T /tmp)
if [ "$TMP_DIR_FS" == "tmpfs" ]; then
    echo "/tmp is mounted as a tmpfs. Need a suitable location for benchmarking file io from disk. Exiting."
    exit
fi

NUM_PROCS=$(nproc)
OUTPUT_FILE="$(pwd)/bench_results_$(hostname)_$(date +%Y-%m-%dT%H-%M-%S).txt"

# Wrapped in code block to reroute all output to log
{

    # CPU tests - 1 vs all
    print_exec sysbench cpu run \
        --threads=1 \
        --time=30 \
        --validate=on

    print_exec sysbench cpu run \
        --threads="$NUM_PROCS" \
        --time=30 \
        --validate=on

    # Mem test - small blocks vs large blocks * single thread vs all threads
    # Why? Large blocks can demonstrate faster mem speeds
    print_exec sysbench memory run \
        --threads=1 \
        --memory-total-size=200G \
        --memory-block-size=4K \
        --validate=on

    print_exec sysbench memory run \
        --threads=1 \
        --memory-total-size=200G \
        --memory-block-size=2M \
        --validate=on

    print_exec sysbench memory run \
        --threads="$NUM_PROCS" \
        --memory-total-size=200G \
        --memory-block-size=4K \
        --validate=on

    print_exec sysbench memory run \
        --threads="$NUM_PROCS" \
        --memory-total-size=200G \
        --memory-block-size=2M \
        --validate=on

    print_exec sysbench memory run \
        --threads="$NUM_PROCS" \
        --memory-total-size=200G \
        --memory-block-size=4K \
        --memory-access-mode=rnd \
        --validate=on

    # File IO test
    ## Benchmarks: sync, mmap, fsync all, fsync every 10th

    ## Use tmp to not junk up CWD
    TEMP_DIR="/tmp/sysbench_$(date +%s)"
    mkdir -p "$TEMP_DIR"
    pushd "$TEMP_DIR" || {
        echo "Unable to create test directory $TEMP_DIR"
        exit 1
    }
    print_exec sysbench fileio prepare --file-test-mode=rndrw

    ## Single threaded
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=sync
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=mmap
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=sync --file-fsync-all=on
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=sync --file-fsync-freq=10

    ## Multi threaded
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=sync --threads="$NUM_PROCS"
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=mmap --threads="$NUM_PROCS"
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=sync --threads="$NUM_PROCS" --file-fsync-all=on
    print_exec sysbench fileio run --file-test-mode=rndrw --file-io-mode=sync --threads="$NUM_PROCS" --file-fsync-freq=10

    print_exec sysbench fileio cleanup
    popd || { exit 1; }
    rmdir "$TEMP_DIR"

} >>"$OUTPUT_FILE"
