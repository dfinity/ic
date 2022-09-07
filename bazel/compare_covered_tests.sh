#!/bin/bash

print_red() {
    echo -e "\033[0;31m$*\033[0m"
}

print_green() {
    echo -e "\033[0;32m$*\033[0m"
}

print_blue() {
    echo -e "\033[1;34m$*\033[0m"
}

info() {
    print_blue "$*"
}

count_total() {
    summary=$(cat $1 | grep '^\(running \)\?[0-9]* test' | grep -o '[0-9]* test' | cut -d ' ' -f 1 | awk '{ sum += $1 } END { print sum }')
    total="$summary"
    echo $total
}

LONG_OUTPUT="false"
OUT_CARGO='out_cargo.txt'
OUT_BAZEL='out_bazel.txt'

if [ "$1" == "--long_output" ]; then
    LONG_OUTPUT="true"
fi

info "---- enumerating CARGO tests..."
cargo test -- --list >$OUT_CARGO
CARGO_COUNT=$(count_total $OUT_CARGO)
info "     Cargo found $CARGO_COUNT test(s)."

info "---- enumerating BAZEL tests..."
bazel test :all --test_arg=--list --test_output=all >$OUT_BAZEL
BAZEL_COUNT=$(count_total $OUT_BAZEL)
info "     Bazel found $BAZEL_COUNT test(s)."

if [ $CARGO_COUNT == $BAZEL_COUNT ]; then
    print_green "SUCCESS: both Cargo and Bazel report $CARGO_COUNT tests"
    if [ "$LONG_OUTPUT" != "true" ]; then
        exit
    fi
else
    print_red "FAILURE: Cargo and Bazel report different numbers of tests"
fi

info "---- CARGO stats:"
print_red "Cargo reports $CARGO_COUNT test(s)"
if [ "$LONG_OUTPUT" == "true" ]; then
    cat out_cargo.txt
else
    cat out_cargo.txt | grep '^[0-9]* test'
fi

info "---- BAZEL stats:"
print_red "Bazel reports $BAZEL_COUNT test(s)"
if [ "$LONG_OUTPUT" == "true" ]; then
    cat out_bazel.txt
else
    cat out_bazel.txt | grep '^[0-9]* test'
fi
