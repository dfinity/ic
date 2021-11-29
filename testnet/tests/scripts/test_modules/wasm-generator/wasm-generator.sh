#!/usr/bin/env bash

# This script randomly generates wasm canisters ready to be installed in the IC
# It uses Csmith to generate C samples that are translated into wasm.
#
# Each new sample computes a random value. Each canister exports a single
# function called "compute" that returns the computed value.
#
# The script takes the number of functions in the sample as an argument. A large number of
# functions means a larger wasm file.
#
# It is best to keep the number of functions bellow 400
#

#
# first let's check we have the right number of args
#
if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <number-of-functions> <number-of-canisters>"
    exit 1
fi

NB_FUNCTIONS=$1
NB_CANISTERS=$2

#
# set Csmith options
#
OPTIONS="--no-pointers --no-math64 --no-int8 --no-uint8 --inline-function --concise --quiet  --no-argc --no-volatiles --no-longlong   --no-unions  --max-funcs $NB_FUNCTIONS --no-structs  --no-volatile-pointers --no-bitfields --no-builtins --concise --quiet --no-jumps"

for i in $(seq 1 $NB_CANISTERS); do
    if [ -f "sample.c" ]; then
        rm -f "sample.*"
    fi

    echo "generating random C program... sample.c"
    timeout 10s csmith $OPTIONS -o sample.c

    if [ -f "sample.c" ]; then
        echo "sample.c succesfully generated"
    else
        echo "failed to generate sample.c "
        exit 0
    fi

    CSMITH_INCLUDE=${CSMITH_INCLUDE:-/usr/include/csmith}
    LIBC_INCLUDE=${LIBC_INCLUDE:-/usr/include}

    echo "compiling random C program with gcc"
    gcc -I "$CSMITH_INCLUDE" -I "$LIBC_INCLUDE" sample.c -o sample -w

    echo "running compiled x86_64 sample"
    timeout 10s ./sample

    echo "preparing sample for IC"
    sed -i'.original' -e 's/platform_main_end(crc32_context ^ 0xFFFFFFFFUL, print_hash_value);/return crc32_context ^ 0xFFFFFFFFUL ;/g' sample.c
    sed -i'.original' -e 's/return 0;//g' sample.c

    echo "compiling random canister C code"
    /usr/lib/llvm-10/bin/clang --target=wasm32 -fno-stack-protector -c -O3 -nostdlib -I "$CSMITH_INCLUDE" -I "$TEST_MODULES/wasm-generator" -I "$LIBC_INCLUDE" -w sample.c
    /usr/lib/llvm-10/bin/clang --target=wasm32 -fno-stack-protector -c -O3 -nostdlib -w "$TEST_MODULES/wasm-generator/"canister.c -I "$TEST_MODULES/wasm-generator" -I "$LIBC_INCLUDE"
    /usr/lib/llvm-10/bin/clang --target=wasm32 -fno-stack-protector -c -O3 -nostdlib -w "$TEST_MODULES/wasm-generator/"libs-src.c -I "$TEST_MODULES/wasm-generator" -I "$LIBC_INCLUDE"
    echo "generating random canister wasm code"
    wasm-ld-10 --no-entry --export-dynamic --allow-undefined libs-src.o canister.o sample.o -o "${RANDOM_CANISTERS_BASE_DIR}/can-$i.wasm"
done
