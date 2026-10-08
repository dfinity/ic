#!/usr/bin/env bash
# Lists the tests that flaked since the previous daily run, or just $LABEL if set, grouped by base test, as
# the matrix of .github/workflows/schedule-fix-flaky-tests.yml. Groups that are missing at HEAD, have an
# open deflake PR or one merged after their last flaky run, or match a regex in $SKIP_PATTERNS (one per line)
# are dropped, and only the first $MAX_FLAKY_TESTS_TO_FIX of the rest are kept.
#
# Prints the groups to stdout and, when run in GitHub Actions, writes them to $GITHUB_OUTPUT as
# `tests` and a summary to $GITHUB_STEP_SUMMARY.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

max_flaky_tests_to_fix="${MAX_FLAKY_TESTS_TO_FIX:?must be set to the number of tests to fix per run}"
if ! [[ "$max_flaky_tests_to_fix" =~ ^[1-9][0-9]*$ ]]; then
    echo "MAX_FLAKY_TESTS_TO_FIX must be a positive integer, not '$max_flaky_tests_to_fix'." >&2
    exit 1
fi

# The workflow runs daily, and the github-stats DB lags up to 3 hours behind CI, so a day plus that lag and an
# hour of cron delay covers the tests that flaked since the previous run.
since="$(date -u -d '28 hours ago' '+%F %T')"
# Lines of a label and the UTC time of its last flaky run, which $LABEL doesn't have.
if [ -n "${LABEL:-}" ]; then
    flaky="$LABEL"
else
    # `--gt 0` applies to flaky% rounded to one decimal, which only hides a flake among more than 2000 runs of a
    # test, while the busiest test ran 488 times in the week of 2026-10-05.
    # The bottom border of the table yields a blank last line. Other lines without a label mean that the table
    # format changed, so they fail the check below instead of silently dropping their tests.
    flaky="$(bazel run //ci/githubstats:query -- top 100 flaky% --gt 0 --since "$since" --columns=label,last_flaky_at | tail -n+4 \
        | awk '{print $4, $7 "T" $8 "Z"}' | sed '$d; s/^ /(no label) /')"
fi
labels="$(cut -d' ' -f1 <<<"$flaky")"

tests='[]'
summary="No test flaked in the last 28 hours."
if [ -n "$flaky" ]; then
    time_re=' [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'
    [ -z "${LABEL:-}" ] || time_re=''
    if invalid="$(grep -Ev "^//[A-Za-z0-9_./-]+:[A-Za-z0-9_./+-]+$time_re\$" <<<"$flaky")"; then
        echo "Invalid labels or times:" >&2
        echo "$invalid" >&2
        exit 1
    fi

    query="set($(sed 's/.*/"&"/' <<<"$labels" | paste -sd' '))"
    # Exit code 3 means some labels don't exist (anymore) at HEAD.
    existing="$(bazel query --keep_going "$query")" || [ $? -eq 3 ]
    long="$(bazel query --keep_going "attr(tags, long_test, $query)")" || [ $? -eq 3 ]

    # All open PRs, and all PRs merged into master after $since, as the title of a PR on a deflake branch may have
    # been edited.
    prs="$(gh pr list --repo dfinity/ic --state open --limit 1000 --json title,headRefName,isCrossRepository,author)"
    merged="$(gh pr list --repo dfinity/ic --base master --state merged --search "merged:>=$(date -u -d "$since" +%FT%TZ)" \
        --limit 1000 --json number,title,headRefName,isCrossRepository,author,mergedAt)"
    if [ "$(jq length <<<"$prs")" -ge 1000 ] || [ "$(jq length <<<"$merged")" -ge 1000 ]; then
        echo "Too many PRs to check." >&2
        exit 1
    fi
    # Anyone who can read the repository can open a PR from one of its branches, and authors can still edit the
    # title after the merge, so only the deflake PRs of claude[bot] and of authors with write access count. The
    # permission field reports maintainers as write.
    trusted="$(jq -r --argjson merged "$merged" '(. + $merged)[] | select((.title | test("deflake"; "i")) or (.headRefName | startswith("ai/deflake-"))) | .author.login' <<<"$prs" \
        | sort -u | while read -r login; do
        permission="$(gh api "repos/dfinity/ic/collaborators/$login/permission" --jq .permission 2>/dev/null || true)"
        if [[ "$login" == app/claude || "$permission" == admin || "$permission" == write ]]; then
            echo "$login"
        fi
    done | jq -R . | jq -s -c .)"
    echo "Trusted the deflake PRs of: $(jq -r 'join(", ")' <<<"$trusted")" >&2

    groups="$(jq -n -c \
        --arg labels "$labels" \
        --arg flaky "$flaky" \
        --arg existing "$existing" \
        --arg long "$long" \
        --argjson prs "$prs" \
        --argjson trusted "$trusted" \
        --argjson merged "$merged" \
        --arg patterns "${SKIP_PATTERNS:-}" \
        --argjson max_flaky_tests_to_fix "$max_flaky_tests_to_fix" '
        def lines: gsub("\r"; "") | split("\n") | map(select(length > 0));
        # Variants of a system-test, like _local and _head_nns_farm_colocate (a bare _head_nns is a legacy
        # name), and copies of a rust_test made by rust_test_with_binary run the same test binary.
        def base:
            (if startswith("//rs/tests/") then sub("(_head_nns)?(_local|_farm|_farm_colocate|_colocate)?$"; "") else . end)
            | sub("_test_binary$"; "_test");
        # Slugs replace the characters that branch and artifact names cannot have and are truncated, so they end in
        # a hash of the label to keep different labels apart.
        def hash: reduce explode[] as $c (0; . * 33 + $c | . - (. / 4294967296 | floor) * 4294967296);
        def hex: [limit(8; recurse(. / 16 | floor)) | . - (. / 16 | floor) * 16] | reverse | map("0123456789abcdef"[.:. + 1]) | add;
        def slug: (ltrimstr("//") | gsub("[^A-Za-z0-9._-]"; "-") | .[:90]) + "-" + (hash | hex);
        # The branches of open-deflake-pr.sh end in the date, so that one of //foo:bar-baz does not count for //foo:bar.
        def deflake_branch($slug):
            ("ai/deflake-" + $slug + "-") as $prefix
            | startswith($prefix) and (ltrimstr($prefix) | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}(-[0-9]+)?$"));

        ($existing | lines) as $existing
        | ($long | lines) as $long
        | ($patterns | lines) as $patterns
        | [$prs[] | select((.isCrossRepository | not) and (.author.login | IN($trusted[])))] as $prs
        | [$prs[].title | capture("deflake `?(?<label>//[^ `,]+)"; "i").label | base] as $pr_bases
        | [$prs[].headRefName] as $pr_heads
        | ($flaky | lines | map(split(" ") | select(length == 2) | {key: .[0], value: .[1]}) | from_entries) as $flaky_at
        # A deflake PR merged after the last flaky run of a test counts even if it leaves a cause for later: its author
        # may be on it, and new flaky runs will show it. Reverts, which name the PRs they revert as (#N) or in their
        # revert-<N>- branch, and the reverted PRs do not count.
        | [$merged[] | select(.title | test("\\brevert\\b"; "i"))
            | (.title | scan("\\(#([0-9]+)\\)")[]), (.headRefName | capture("^revert-(?<n>[0-9]+)-").n) | tonumber] as $reverted
        | [$merged[] | select((.isCrossRepository | not) and (.author.login | IN($trusted[]))
                and (.title | test("\\brevert\\b"; "i") | not) and (.number | IN($reverted[]) | not))
            | {number, mergedAt, headRefName, base: ([.title | capture("deflake `?(?<label>//[^ `,]+)"; "i").label | base] | first)}] as $merged
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
            | ([.labels[] | $flaky_at[.] // empty] | max) as $last_flaky_at
            | ([$merged[] | select($last_flaky_at != null and .mergedAt > $last_flaky_at
                and (.base == $base or (.headRefName | deflake_branch($slug))))] | first) as $fix
            | {
                label: $present[0],
                labels: ($present | join(" ")),
                $base,
                $slug,
                ci_all_bazel_targets: any($present[]; IN($long[])),
                missing: (.labels - $present),
                drop: (
                    if $present == [] then "missing at HEAD"
                    elif ($base | IN($pr_bases[])) or any($pr_heads[]; deflake_branch($slug))
                    then "has an open deflake PR"
                    elif $fix != null then "fixed by #\($fix.number) after its last flaky run"
                    elif any($patterns[]; . as $p | any($base, $present[]; test($p)))
                    then "matches FIX_FLAKY_TESTS_SKIP_PATTERNS"
                    else null
                    end
                )
            }
        )
        | if (map(.slug) | unique | length) != length then error("duplicate slugs") else . end
        # An incident can make many tests flaky at once, like 60 on 2026-10-02, and fixing them all, 4 at a time
        # and up to 4 hours each, would keep the run busy for days.
        | [foreach .[] as $group (0; . + if $group.drop == null then 1 else 0 end;
            if $group.drop == null and . > $max_flaky_tests_to_fix then $group + {drop: "over the limit of \($max_flaky_tests_to_fix) tests"} else $group end)]')"

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
