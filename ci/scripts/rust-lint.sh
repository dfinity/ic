#!/usr/bin/env bash
set -xeuo pipefail

cd "${CI_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

cargo fmt -- --check

if ! ci/scripts/cargo-clippy.sh; then
    # Don't just explode: provide a solution. Our job is to provide
    # solid gold, not raw ore.
    cat <<EOF

========================================
$(printf '\033[1;31m')Clippy violations found!$(printf '\033[0m')

$(printf '\033[1;32m')To automatically fix many of these, run:

    ci/scripts/cargo-clippy.sh --fix --allow-dirty$(printf '\033[0m')

On PRs this will be run automatically by the 'autofix' job.
========================================
EOF
    exit 1
fi

if cargo tree --workspace --depth 1 -e features | grep -q 'serde feature "rc"'; then
    echo 'The serde "rc" feature seems to be enabled. Instead, the module "serde_arc" in "ic-utils" should be used.'
    exit 1
fi

cargo run -q -p depcheck
