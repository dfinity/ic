#!/usr/bin/env bash

set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <DIR>
    DIR: Directory containing text files (e.g. nns-governance.md).

    Takes the contents of all files, surounds them with six ticks, gives a
    heading to each (based on the file name), concatenates them all, and sticks
    the result in your clipboard.

    (You'll probably want to manually want to manually insert links to proposals
    afterwards.)

"
    exit 1
}

if [[ $# -ne 1 ]]; then
    help
fi

PROPOSALS_DIR="${1}"

if ! which gsed &>/dev/null; then
    echo 'gsed is required. Install like so: brew install gnu-sed.'
    exit 1
fi

first=true
for FILE in $(ls "${PROPOSALS_DIR}"); do
    # Separate from previous.
    if [[ "${first}" == true ]]; then
        first=false
    else
        echo
        echo
    fi

    echo '#' $(
        basename "${FILE}" \
            | sed 's/.md//' \
            | sed 's/-/ /g' \
            | sed 's/nns/NNS/' \
            | sed 's/sns/SNS/' \
            | gsed -E 's/\b./\U\0/g'
    )
    echo
    echo '``````'
    cat "${PROPOSALS_DIR}/${FILE}"
    echo '``````'
done \
    | pbcopy

SIZE=$(pbpaste | wc -c)

echo "👍 Your clipboard now has ${SIZE} bytes in it. Use them wisely, only for good, never evil. 😇"
