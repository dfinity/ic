#!/bin/bash

print_red() {
    echo -e "\033[0;31m$*\033[0m" 1>&2
}

print_green() {
    echo -e "\033[0;32m$*\033[0m"
}

print_blue() {
    echo -e "\033[0;34m$*\033[0m"
}

info() {
    print_blue $*
}

LONG_OUTPUT="false"

if [ "$1" == "--long_output" ]; then
    LONG_OUTPUT="true"
fi

info "---- enumerating CARGO tests..."
cargo test -- --list >out_cargo.txt

info "---- enumerating BAZEL tests..."
bazel test :all --test_arg=--list --test_output=all >out_bazel.txt

info "---- CARGO stats:"
if [ "$LONG_OUTPUT" == "true" ]; then
    cat out_cargo.txt
else
    cat out_cargo.txt | grep '^[0-9]* tests'
fi

info "---- BAZEL stats:"
if [ "$LONG_OUTPUT" == "true" ]; then
    cat out_bazel.txt
else
    cat out_bazel.txt | grep -e 'Test output for' -e '^[0-9]* tests'
fi
