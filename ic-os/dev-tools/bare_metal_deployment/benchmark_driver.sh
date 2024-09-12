#!/usr/bin/env bash
set -eEuo pipefail

benchmark_runner="${1}"
ssh_key="${2}"
ip_address="${3}"
tools="${@:4}"

key_component=()
if [ "${ssh_key}" != "None" ]; then
    key_component=("-i", "${ssh_key}")
fi

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" exit

# Send over the runner
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${key_component[@]}" "${benchmark_runner}" "admin@[${ip_address}]:benchmark_runner.sh"

# Send over the tools
if [ "${tools}" != "" ]; then
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${key_component[@]}" "${tools[@]}" "admin@[${ip_address}]:"
fi

# Run benchmarking
echo >&2 "Benchmarking node..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${key_component[@]}" "admin@${ip_address}" "sudo ./benchmark_runner.sh"

# Collect results
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${key_component[@]}" -r "admin@[${ip_address}]:results" "${TMPDIR}"

# Output results
echo "-------------------- Benchmark Results --------------------"
cat ${TMPDIR}/results/*
echo "-----------------------------------------------------------"
