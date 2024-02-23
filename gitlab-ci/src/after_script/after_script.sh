#!/usr/bin/env bash

set -eEuo pipefail

test -z "${SSH_AUTH_SOCK:-}" && {
    eval "$(ssh-agent -s)"
    ssh-add - <<<"${SSH_PRIVATE_KEY}"
}
ssh-add -L || true
date
export PYTHONPATH="${CI_PROJECT_DIR}/gitlab-ci/src"

ENG_CONS_CHANNEL="eng-consensus-test-failures"
INGRESS_MNGR_PROPTEST_NAME="ingress-manager-proptests-nightly"
cd "${CI_PROJECT_DIR}" || true

git checkout --detach --force "$CI_COMMIT_SHA"

# send slack messages
debug=""
[ -n "${DEBUG_PIPELINE:-}" ] && debug="DEBUG "
MESSAGE="Scheduled ${debug}job \`$CI_JOB_NAME\` *failed*. <$CI_JOB_URL|log>. Commit: <$CI_PROJECT_URL/-/commit/$CI_COMMIT_SHA|$CI_COMMIT_SHORT_SHA>."

if [[ "$CI_PIPELINE_SOURCE" == "schedule" ]] && [[ "$CI_JOB_STATUS" == "failed" ]] && [[ ! -f "${CI_PROJECT_DIR}/test-results.json" ]]; then
    cd "${CI_PROJECT_DIR}/gitlab-ci/src" || true
    # We support multiple comma separated slack channels in the SLACK_CHANNEL variable.
    IFS=',' read -ra CHANNELS <<<"${SLACK_CHANNEL:-}"
    for channel in "${CHANNELS[@]}"; do
        notify_slack/notify_slack.py "$MESSAGE" --channel "$channel" || true
    done
fi

# send slack messages for specific test signals
if [[ "$CI_JOB_STATUS" == "failed" ]]; then
    cd "${CI_PROJECT_DIR}/gitlab-ci/src" || true
    # and old bash-test that was introduced with OR-187, failures are dispatched to OR-team directly
    # test signals for ingress manager proptests are sent to CONS directly
    if [[ "$CI_JOB_NAME" == "$INGRESS_MNGR_PROPTEST_NAME" ]]; then
        notify_slack/notify_slack.py "$MESSAGE" --channel "$ENG_CONS_CHANNEL" || true
    fi
fi

# Export additional honeycomb metrics.
STEP_START_RAW=$(curl -H "PRIVATE-TOKEN: $GITLAB_API_TOKEN" "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/jobs/$CI_JOB_ID" | jq '.started_at | sub("\\.[0-9]+Z$"; "Z")' | sed 's/"//g')
PIPELINE_START_TIME_RAW=$(curl -H "PRIVATE-TOKEN: $GITLAB_API_TOKEN" "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/pipelines/$ROOT_PIPELINE_ID" | jq '.created_at | sub("\\.[0-9]+Z$"; "Z")' | sed 's/"//g')

if [ "$(uname)" == "Darwin" ]; then
    STEP_START=$(/usr/local/bin/gdate -d "$STEP_START_RAW" +%s)
    PIPELINE_START_TIME=$(/usr/local/bin/gdate -d "$PIPELINE_START_TIME_RAW" +%s)
else
    STEP_START=$(date -d "$STEP_START_RAW" +%s)
    PIPELINE_START_TIME=$(date -d "$PIPELINE_START_TIME_RAW" +%s)
fi

export STEP_START
export PIPELINE_START_TIME

# Key the file to the job id. Darwin builders do not run in jobs in Docker, and could
# stomp eachother's file.
export BUILDEVENT_FILE="/tmp/buildevents-step-file-${CI_JOB_ID}"
python3 "${CI_PROJECT_DIR}"/gitlab-ci/src/log_metrics/gen_honeycomb_metrics.py >"$BUILDEVENT_FILE"

buildevents step "$ROOT_PIPELINE_ID" "$CI_JOB_ID" "$STEP_START" "$CI_JOB_NAME"

if [[ "$CI_JOB_NAME" == "notify-gitlab-success" ]] || [[ "$CI_JOB_NAME" == "notify-gitlab-failure" ]]; then
    PIPELINE_STATUS=$(echo "$CI_JOB_NAME" | cut -d'-' -f3) # success or failure
    buildevents build "$ROOT_PIPELINE_ID" "$PIPELINE_START_TIME" "$PIPELINE_STATUS"
fi
