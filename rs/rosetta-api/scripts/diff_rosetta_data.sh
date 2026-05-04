#!/usr/bin/env bash

# Compare the two databases created by rosetta
# Specifically compares the block table which
# is the one that matters.
#
# Note: a new ledger operation may happen between fetching the
# old blocks and the new blocks. Therefore we check only the block
# that are in old

set -euo pipefail
set -x

if (($# != 2)); then
    echo >&2 "Usage: $0 <rosetta_db_old> <rosetta_db_new>"
    exit 1
fi

ROSETTA_DB_OLD="$1"
ROSETTA_DB_NEW="$2"

if [ ! -f "$ROSETTA_DB_OLD" ]; then
    echo >&2 "File $ROSETTA_DB_OLD does not exist"
    exit 2
fi

if [ ! -f "$ROSETTA_DB_NEW" ]; then
    echo >&2 "File $ROSETTA_DB_NEW does not exist"
    exit 3
fi

last_block_to_check=$(sqlite3 "$ROSETTA_DB_OLD" 'select max(block_idx) from blocks')

QUERY="select hex(block_hash), hex(encoded_block), hex(parent_hash), block_idx, verified from blocks"

diff \
    <(sqlite3 "$ROSETTA_DB_OLD" "$QUERY") \
    <(sqlite3 "$ROSETTA_DB_NEW" "$QUERY where block_idx <= $last_block_to_check")

RES=$?

if [ "$RES" -eq 0 ]; then
    echo "The two databases contain the same blocks up to block $last_block_to_check"
    exit $RES
else
    echo >&2 "The two databases contain different blocks! Last block checked is $last_block_to_check"
    exit $RES
fi
