#!/usr/bin/env bash
# Validates the fix that .github/workflows/fix-flaky-test.yml bundled in $RUNNER_TEMP/deflake and
# prepares its PR for ci/scripts/open-deflake-pr.sh: the fix is squashed into one commit on top of
# $BASE_SHA and only its tree and PR body come from the bundle. The branch, title and labels are
# derived from the trusted $SLUG, $RUN_DATE, $LABEL and $LABELS. Exports BRANCH, NEW, TITLE and
# BODY_FILE to $GITHUB_ENV.

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
# fix-flaky-test.yml squashes the fix, so that the public artifact has no intermediate commits.
[ "$(git rev-list --count "$BASE_SHA..$fix")" -eq 1 ] || die "the fix isn't a single commit"
! git diff --quiet "$BASE_SHA" "$fix" || die "the fix doesn't change anything"

# The diffs are captured before checking them so that a failing git diff aborts the script, and a grep
# exiting early can't SIGPIPE git into a pipeline failure that reads as "no match".
git diff --no-renames --name-only -z "$BASE_SHA" "$fix" >"$RUNNER_TEMP/deflake-paths"
disallowed=()
while IFS= read -r -d '' path; do
    case "$path" in
        # The files that define Bazel modules and repositories, wherever they are.
        MODULE.bazel | */MODULE.bazel | *.MODULE.bazel | *MODULE.bazel.lock | REPO.bazel | */REPO.bazel | WORKSPACE | */WORKSPACE | *WORKSPACE.bazel)
            disallowed+=("$path")
            ;;
        # Dependency configuration besides Cargo.toml and the root Cargo.lock, which are validated below.
        */.cargo/config | */.cargo/config.toml | */rust-toolchain | */rust-toolchain.toml | */*.lock | */requirements*.txt | */pyproject.toml | */package.json | */package-lock.json | */go.mod | */go.sum)
            disallowed+=("$path")
            ;;
        *.bzl | *.bazelrc | .gitattributes | */.gitattributes | .gitmodules | rs/ic_os/config/types/*)
            disallowed+=("$path")
            ;;
        rs/* | packages/* | ic-os/* | Cargo.lock) ;;
        *) disallowed+=("$path") ;;
    esac
done <"$RUNNER_TEMP/deflake-paths"
[ ${#disallowed[@]} -eq 0 ] || die "the fix changes disallowed files: ${disallowed[*]}"
raw="$(git diff --no-renames --raw "$BASE_SHA" "$fix")"
if awk '$1 ~ /^:(120000|160000)$/ || $2 == "120000" || $2 == "160000" {bad = 1} END {exit !bad}' <<<"$raw"; then
    die "the fix changes a symlink or submodule"
fi
"$(dirname "$0")/validate-deflake-dependencies.py" "$BASE_SHA" "$fix" || die "the fix changes dependencies beyond adding or removing workspace dependencies"
numstat="$(git diff --no-renames --numstat "$BASE_SHA" "$fix")"
if grep -q $'^-\t-\t' <<<"$numstat"; then
    die "the fix changes binary files"
fi
changed="$(awk '{n += $1 + $2} END {print n + 0}' <<<"$numstat")"
[ "$changed" -le 1000 ] || die "the fix changes $changed lines"
# Lines can be arbitrarily long.
bytes="$(git diff --no-renames "$BASE_SHA" "$fix" | wc -c)"
[ "$bytes" -le 1000000 ] || die "the diff of the fix has $bytes bytes"

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
    # Keep the first 60000 characters, decoding leniently since malformed UTF-8, like a character split by the
    # byte limit, is fatal to Perl's regexes. Then drop what could hide text from reviewers: HTML comments (also
    # unterminated ones), link reference definitions (which also serve as comments), the tags of collapsed sections
    # and invisible, private-use or unassigned characters.
    head -c 240000 "$RUNNER_TEMP/deflake/body.md" \
        | perl -0777 -CO -MEncode -pe '$_ = substr(decode("UTF-8", $_), 0, 60000); 1 while s/<!--.*?(?:-->|\z)//s; s/^ {0,3}\[[^\]\n]*\]:.*\n?//mg; s{</?(?:details|summary)\b[^>]*>}{}gi; s/[\p{Cf}\p{Co}\p{Cn}\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]//g'
} >"$body_file"

{
    echo "BRANCH=ai/deflake-$SLUG-$RUN_DATE"
    echo "NEW=$new"
    echo "TITLE=$title"
    echo "BODY_FILE=$body_file"
} >>"$GITHUB_ENV"
