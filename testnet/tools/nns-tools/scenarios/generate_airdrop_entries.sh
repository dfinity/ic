#!/bin/bash

set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

ensure_variable_set SNS_QUILL

for i in {1..2000}; do
    PRINCIPAL=$($SNS_QUILL generate --overwrite-pem-file --overwrite-seed-file | grep "Principal id:" | cut -d" " -f3)
    echo "        - controller: $PRINCIPAL"
    echo "          stake_e8s: 20000"
    echo "          memo: 0"
    echo "          dissolve_delay_seconds: 15780000 # 6 months"

done
