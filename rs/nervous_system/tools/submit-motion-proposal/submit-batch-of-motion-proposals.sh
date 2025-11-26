#!/usr/bin/env bash
set -Eeuo pipefail

help() {
    echo "
Usage: $0 <NEURON_ID> <DIRECTORY>
    NEURON_ID: The ID of the neuron that you want to submit with.
    DIRECTORY: Path to a directory containing all the proposal files that you
        want to submit, each in the format required by submit-motion-proposal.
  "
    exit 1
}

if [ $# -ne 2 ]; then
    help
fi

NEURON_ID=$1
DIRECTORY=$2

print_separator() {
    echo --------------------------------------------------------------------------------
}

echo "Please, enter your HSM PIN."
echo "(It will not appear as you type it; neverthless, press enter when done.)"
read -s DFX_HSM_PIN
export DFX_HSM_PIN

bazel build \
    //rs/nervous_system/tools/submit-motion-proposal

print_separator
for FILE in "${DIRECTORY}"/*; do
    echo "File: ${FILE}"

    ./bazel-bin/rs/nervous_system/tools/submit-motion-proposal/submit-motion-proposal \
        --neuron-id="${NEURON_ID}" \
        --proposal-file="${FILE}" \
        --verbose

    print_separator
done

echo
echo "All proposals have been submitted 🎉"
