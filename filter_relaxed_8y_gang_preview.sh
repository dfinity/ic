#!/usr/bin/env bash

set -euo pipefail

grep PREVIEW_RELAXED_EIGHT_YEAR_GANG /tmp/golden_run.txt \
| sed 's/.*PREVIEW_RELAXED_EIGHT_YEAR_GANG //' \
| jq -s '.' \
> preview_8y_gang.json