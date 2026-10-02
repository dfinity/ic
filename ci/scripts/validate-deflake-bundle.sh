#!/usr/bin/env bash
# Validates the fix that .github/workflows/fix-flaky-test.yml bundled in $RUNNER_TEMP/deflake and
# prepares its PR for ci/scripts/open-deflake-pr.sh: the fix is squashed into one commit on top of
# $BASE_SHA and only its tree and PR body come from the bundle. The branch, title and labels are
# derived from the trusted $SLUG, $LABEL and $LABELS. Exports BRANCH, NEW, TITLE and BODY_FILE to
# $GITHUB_ENV.

set -euo pipefail

die() {
    echo "needs_human: $*" >&2
    exit 1
}

bundle="$RUNNER_TEMP/deflake/deflake.bundle"
git fetch --quiet --depth=1 origin "$BASE_SHA"

# The header of the bundle lists its prerequisites (lines starting with '-') and its refs.
header="$(sed '/^$/q' "$bundle")"
[ "$(grep '^-' <<<"$header" | cut -c2-41)" == "$BASE_SHA" ] || die "the bundle doesn't build on $BASE_SHA"
[ "$(git bundle list-heads "$bundle" | cut -d' ' -f2-)" == refs/heads/deflake ] || die "the bundle has other refs than refs/heads/deflake"

fix=refs/deflake/fix
git -c transfer.fsckObjects=true fetch --quiet "$bundle" "+refs/heads/deflake:$fix" || die "the bundle can't be fetched"
git merge-base --is-ancestor "$BASE_SHA" "$fix" || die "the fix isn't on top of $BASE_SHA"
[ "$(git rev-list --count "$BASE_SHA..$fix")" -le 10 ] || die "the fix has more than 10 commits"

# The diffs are captured before checking them so that a failing git diff aborts the script, and a grep
# exiting early can't SIGPIPE git into a pipeline failure that reads as "no match".
git diff --no-renames --name-only -z "$BASE_SHA" "$fix" >"$RUNNER_TEMP/deflake-paths"
disallowed=()
while IFS= read -r -d '' path; do
    case "$path" in
        *.bzl | MODULE.bazel | *.MODULE.bazel | *.bazelrc | .gitattributes | */.gitattributes | .gitmodules | rs/ic_os/config/types/*)
            disallowed+=("$path")
            ;;
        rs/* | packages/* | Cargo.lock) ;;
        *) disallowed+=("$path") ;;
    esac
done <"$RUNNER_TEMP/deflake-paths"
[ ${#disallowed[@]} -eq 0 ] || die "the fix changes disallowed files: ${disallowed[*]}"
raw="$(git diff --no-renames --raw "$BASE_SHA" "$fix")"
if awk '$2 == "120000" || $2 == "160000" {bad = 1} END {exit !bad}' <<<"$raw"; then
    die "the fix adds a symlink or submodule"
fi
# Dependencies may only be added or removed as `name = { workspace = true }`, whose versions and features come
# from the root Cargo.toml, which the fix can't change.
manifests="$(git diff --no-renames --unified=0 "$BASE_SHA" "$fix" -- '*Cargo.toml')"
if awk '
    /^(\+\+\+|---) / { next }
    /^[+-]/ {
        line = substr($0, 2)
        if (line !~ /^[ \t]*$/ && line !~ /^[ \t]*\[[A-Za-z0-9_.-]+\][ \t]*$/ \
            && line !~ /^[ \t]*[A-Za-z0-9_-]+[ \t]*=[ \t]*\{[ \t]*workspace[ \t]*=[ \t]*true[ \t]*\}[ \t]*$/ \
            && line !~ /^[ \t]*[A-Za-z0-9_-]+\.workspace[ \t]*=[ \t]*true[ \t]*$/) bad = 1
    }
    END { exit !bad }' <<<"$manifests"; then
    die "the fix changes a Cargo.toml beyond adding or removing workspace dependencies"
fi
lock="$(git diff "$BASE_SHA" "$fix" -- Cargo.lock)"
if grep -qE '^\+[[:space:]]*(\[\[[[:space:]]*package[[:space:]]*\]\]|(name|version|source|checksum)[[:space:]]*=)' <<<"$lock"; then
    die "the fix changes the dependencies in Cargo.lock"
fi
numstat="$(git diff --no-renames --numstat "$BASE_SHA" "$fix")"
if grep -q $'^-\t-\t' <<<"$numstat"; then
    die "the fix changes binary files"
fi
changed="$(awk '{n += $1 + $2} END {print n + 0}' <<<"$numstat")"
[ "$changed" -le 1000 ] || die "the fix changes $changed lines"

author='claude[bot]'
email='209825114+claude[bot]@users.noreply.github.com'
title="fix: deflake $LABEL"
new="$(GIT_AUTHOR_NAME="$author" GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_NAME="$author" GIT_COMMITTER_EMAIL="$email" \
    git commit-tree "$fix^{tree}" -p "$BASE_SHA" -m "$title")"

body_file="$RUNNER_TEMP/pr-body.md"
{
    echo "This PR was created by $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$RUN_ID following \`.claude/skills/fix-flaky-tests/SKILL.md\` to deflake:"
    for label in $LABELS; do
        echo "* \`$label\`"
    done
    echo
    # Drop what could hide text from reviewers: HTML comments (also unterminated ones), link reference
    # definitions (which also serve as comments) and invisible, private-use or unassigned characters.
    head -c 60000 "$RUNNER_TEMP/deflake/body.md" \
        | perl -0777 -CSD -pe '1 while s/<!--.*?(?:-->|\z)//s; s/^ {0,3}\[[^\]\n]*\]:.*\n?//mg; s/[\p{Cf}\p{Co}\p{Cn}\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]//g'
} >"$body_file"

{
    echo "BRANCH=ai/deflake-$SLUG-$(date -u +%F)"
    echo "NEW=$new"
    echo "TITLE=$title"
    echo "BODY_FILE=$body_file"
} >>"$GITHUB_ENV"
