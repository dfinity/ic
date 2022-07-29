#!/usr/bin/env bash

set -euo pipefail

cat "$@" | xargs -I % curl --head --location %
