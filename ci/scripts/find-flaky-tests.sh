#!/usr/bin/env bash
# Lists the tests that flaked in the last week, or just $LABEL if set, grouped by base test, as the
# matrix of .github/workflows/schedule-fix-flaky-tests.yml. Groups that already have an open deflake
# PR, or that match a regex in $SKIP_PATTERNS (one per line), are dropped.
#
# Prints the groups to stdout and, when run in GitHub Actions, writes them to $GITHUB_OUTPUT as
# `tests` and a summary to $GITHUB_STEP_SUMMARY.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ -n "${LABEL:-}" ]; then
    labels="$LABEL"
else
    # The bottom border of the table yields an empty last line. Other empty lines mean that the table format
    # changed, so they fail the check below instead of silently dropping their tests.
    labels="$(bazel run //ci/githubstats:query -- top 100 flaky% --gt 0 --week --columns=label | tail -n+4 | awk '{print $4}' \
        | sed '$d; s/^$/(no label)/')"
fi

tests='[]'
summary="No test flaked in the last week."
if [ -n "$labels" ]; then
    if invalid="$(grep -Ev '^//[A-Za-z0-9_./-]+:[A-Za-z0-9_./+-]+$' <<<"$labels")"; then
        echo "Invalid labels:" >&2
        echo "$invalid" >&2
        exit 1
    fi

    query="set($(sed 's/.*/"&"/' <<<"$labels" | paste -sd' '))"
    # Exit code 3 means some labels don't exist (anymore) at HEAD.
    existing="$(bazel query --keep_going "$query")" || [ $? -eq 3 ]
    long="$(bazel query --keep_going "attr(tags, long_test, $query)")" || [ $? -eq 3 ]

    prs="$(gh pr list --repo dfinity/ic --state open --search 'deflake in:title' --limit 1000 \
        --json title,headRefName,isCrossRepository)"
    if [ "$(jq length <<<"$prs")" -ge 1000 ]; then
        echo "Too many open deflake PRs to check." >&2
        exit 1
    fi

    groups="$(jq -n -c \
        --arg labels "$labels" \
        --arg existing "$existing" \
        --arg long "$long" \
        --argjson prs "$prs" \
        --arg patterns "${SKIP_PATTERNS:-}" '
        def lines: gsub("\r"; "") | split("\n") | map(select(length > 0));
        # Variants of a system-test, like _local and _head_nns_farm_colocate (a bare _head_nns is a legacy
        # name), and copies of a rust_test made by rust_test_with_binary run the same test binary.
        def base:
            (if startswith("//rs/tests/") then sub("(_head_nns)?(_local|_farm|_farm_colocate|_colocate)?$"; "") else . end)
            | sub("_test_binary$"; "_test");
        def slug: ltrimstr("//") | gsub("[^A-Za-z0-9._-]"; "-") | .[:100];

        ($existing | lines) as $existing
        | ($long | lines) as $long
        | ($patterns | lines) as $patterns
        | [$prs[] | select(.isCrossRepository | not)] as $prs
        | [$prs[].title | capture("deflake `?(?<label>//[^ `,]+)"; "i").label | base] as $pr_bases
        | [$prs[].headRefName] as $pr_heads
        | $labels | lines
        | to_entries
        | map({i: .key, label: .value, base: (.value | base)})
        | group_by(.base)
        | map({i: (map(.i) | min), base: .[0].base, labels: (sort_by(.i) | map(.label))})
        | sort_by(.i)
        | map(
            .base as $base
            | ($base | slug) as $slug
            | (.labels | map(select(IN($existing[])))) as $present
            | {
                label: $present[0],
                labels: ($present | join(" ")),
                $base,
                $slug,
                ci_all_bazel_targets: any($present[]; IN($long[])),
                missing: (.labels - $present),
                drop: (
                    if $present == [] then "missing at HEAD"
                    elif ($base | IN($pr_bases[])) or any($pr_heads[]; startswith("ai/deflake-" + $slug + "-"))
                    then "has an open deflake PR"
                    elif any($patterns[]; . as $p | any($base, $present[]; test($p)))
                    then "matches FIX_FLAKY_TESTS_SKIP_PATTERNS"
                    else null
                    end
                )
            }
        )
        | if (map(.slug) | unique | length) != length then error("duplicate slugs") else . end')"

    tests="$(jq -c 'map(select(.drop == null) | del(.missing, .drop))' <<<"$groups")"
    summary="$(jq -r '
        "| Test | Labels | Fix? |",
        "| - | - | - |",
        (.[] | "| `\(.base)` | \(.labels | split(" ") | map("`\(.)`") | join(" ")) \(.missing | map("~~`\(.)`~~") | join(" ")) | \(.drop // "yes") |")
        ' <<<"$groups")"
fi

echo "$tests" | jq .
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "tests=$tests" >>"$GITHUB_OUTPUT"
    echo "$summary" >>"$GITHUB_STEP_SUMMARY"
fi
