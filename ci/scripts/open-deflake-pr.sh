#!/usr/bin/env bash
# Pushes the commit that ci/scripts/validate-deflake-bundle.sh prepared and opens it as a draft PR.
# .github/workflows/open-deflake-pr.yml runs it through claude-code-action because that is how the
# PR gets authored by claude[bot]: the action sets up git and GH_TOKEN with a claude[bot] token.
# Reads BRANCH, NEW, TITLE, BODY_FILE, ADD_LABEL and RUN_ID from the environment.

set -euo pipefail

[[ "$BRANCH" =~ ^ai/deflake-[A-Za-z0-9._-]+$ ]] || {
    echo "Refusing to push to $BRANCH" >&2
    exit 1
}

open_pr() {
    gh pr list --repo "$GITHUB_REPOSITORY" --head "$1" --state open --json url,isCrossRepository \
        --jq 'map(select(.isCrossRepository | not))[0].url // empty'
}

# Prints the tree of branch $1 if it exists.
branch_tree() {
    local commit
    commit="$(git ls-remote --heads origin "refs/heads/$1" | awk -v ref="refs/heads/$1" '$2 == ref {print $1}')" || return
    [ -z "$commit" ] || gh api "repos/$GITHUB_REPOSITORY/git/commits/$commit" --jq .tree.sha
}

# The branch and its PR are reused when this workflow runs again for the same fix, but another fix of the
# same test on the same day gets a branch of its own.
tree="$(git rev-parse "$NEW^{tree}")"
existing="$(branch_tree "$BRANCH")"
if [ -n "$existing" ] && [ "$existing" != "$tree" ]; then
    BRANCH="$BRANCH-$RUN_ID"
    existing="$(branch_tree "$BRANCH")"
fi
if [ -z "$existing" ]; then
    git push --quiet origin "$NEW:refs/heads/$BRANCH"
elif [ "$existing" != "$tree" ]; then
    echo "$BRANCH already has another fix" >&2
    exit 1
fi

url="$(open_pr "$BRANCH")"
if [ -z "$url" ]; then
    args=(--repo "$GITHUB_REPOSITORY" --draft --base master --head "$BRANCH" --title "$TITLE" --body-file "$BODY_FILE")
    if [ "$ADD_LABEL" == true ]; then
        args+=(--label CI_ALL_BAZEL_TARGETS)
    fi
    url="$(gh pr create "${args[@]}" | tail -n1)"
    gh api --silent --method POST "repos/$GITHUB_REPOSITORY/pulls/${url##*/}/requested_reviewers" \
        --raw-field 'reviewers[]=copilot-pull-request-reviewer[bot]' \
        || echo "Warning: requesting a review from Copilot failed" >&2
fi

jq -n --arg branch "$BRANCH" --arg url "$url" '{$branch, $url}' >"$RUNNER_TEMP/deflake-pr.json"
echo "$url"
