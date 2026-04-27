#!/usr/bin/env bash

set -euo pipefail

bazel test \
  --test_env=SSH_AUTH_SOCK \
  --test_output=streamed \
  --test_arg=--nocapture \
  --nocache_test_results \
  //rs/nns/integration_tests:upgrade_canisters_with_golden_nns_state \
| grep PREVIEW_RELAXED_EIGHT_YEAR_GANG \
| sed 's/.*PREVIEW_RELAXED_EIGHT_YEAR_GANG //' \
| jq -s '.' \
> preview_relaxed_8y_gang.json