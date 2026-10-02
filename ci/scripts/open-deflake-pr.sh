#!/usr/bin/env bash
# Pushes the commit that ci/scripts/validate-deflake-bundle.sh prepared and opens it as a draft PR.
# .github/workflows/open-deflake-pr.yml runs it through claude-code-action because that is how the
# PR gets authored by claude[bot]: the action sets up git and GH_TOKEN with a claude[bot] token.
# Reads BRANCH, NEW, TITLE, BODY_FILE and ADD_LABEL from the environment.

set -euo pipefail

[[ "$BRANCH" =~ ^ai/deflake-[A-Za-z0-9._-]+$ ]] || {
    echo "Refusing to push to $BRANCH" >&2
    exit 1
}

open_pr() {
    gh pr list --repo "$GITHUB_REPOSITORY" --head "$1" --state open --json url,isCrossRepository \
        --jq 'map(select(.isCrossRepository | not))[0].url // empty'
}

url="$(open_pr "$BRANCH")"
if [ -z "$url" ]; then
    if git ls-remote --exit-code --heads origin "refs/heads/$BRANCH" >/dev/null; then
        BRANCH="$BRANCH-$GITHUB_RUN_ID"
    fi
    git push --quiet origin "$NEW:refs/heads/$BRANCH"
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
