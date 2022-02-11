#!/usr/bin/env bash

set -eEuo pipefail

test -z "${SSH_AUTH_SOCK:-}" && {
    eval "$(ssh-agent -s)"
    ssh-add - <<<"${SSH_PRIVATE_KEY}"
}
ssh-add -L || true
date
end=$(date +%s)
export PYTHONPATH="${CI_PROJECT_DIR}/gitlab-ci/src"

CARGO_TEST_JSON="${CI_PROJECT_DIR}/rs/ci_output.json"
CARGO_TEST_JUNIT_XML="${CI_PROJECT_DIR}/test_report.xml"
PREFIX="${CI_PROJECT_DIR}/gitlab-ci/src"
cd "${CI_PROJECT_DIR}" || true
JUNIT_DATA_DIR=${CI_PROJECT_DIR}/junit_data
mkdir -p "$JUNIT_DATA_DIR"

if [[ -d "${CI_PROJECT_DIR}/rs/ci_output" ]]; then
    find "${CI_PROJECT_DIR}/rs/ci_output" -name stdout -exec cat '{}' \; >>"${CARGO_TEST_JSON}"
fi

if [[ -f "$CARGO_TEST_JSON" ]]; then
    python3 "$PREFIX/cargo_test_json_parser/cargo_test_json_parser.py" --input "$CARGO_TEST_JSON" --generate-junit-xml --out "$CARGO_TEST_JUNIT_XML" || {
        cat "$CARGO_TEST_JSON"
        if [[ "$CI_COMMIT_REF_NAME" == "master" ]] || [[ "$CI_COMMIT_REF_NAME" == "post-merge-tests-passed" ]]; then
            "$PREFIX/notify_slack/notify_slack.py" "junit generation failed in <$CI_JOB_URL|$CI_JOB_NAME>." --channel "#precious-bots"
        fi
    }
    cp "$CARGO_TEST_JSON" "$JUNIT_DATA_DIR/ci_results_$CI_JOB_NAME.json"
    mkdir -p "$PREFIX/data_to_upload"
    python3 "$PREFIX/cargo_test_json_parser/cargo_test_json_parser.py" --input "$CARGO_TEST_JSON" --to-log-metrics --out "$PREFIX/data_to_upload/ci_results.json"
fi
if [[ -f "$CARGO_TEST_JUNIT_XML" ]]; then
    cp "$CARGO_TEST_JUNIT_XML" "$JUNIT_DATA_DIR/test_report_$CI_JOB_NAME.xml"
fi
git checkout --detach --force "$CI_COMMIT_SHA"

if [[ "$CI_PIPELINE_SOURCE" == "schedule" ]] && [[ "$CI_JOB_STATUS" == "failed" ]] && [ -n "$SLACK_CHANNEL" ] && [[ "${FARM_BASED:-}" != "true" ]]; then
    cd "${CI_PROJECT_DIR}/gitlab-ci/src" || true
    # We support multiple comma separated slack channels in the SLACK_CHANNEL variable.
    debug=""
    [ -n "${DEBUG_PIPELINE:-}" ] && debug="DEBUG "
    IFS=',' read -ra CHANNELS <<<"$SLACK_CHANNEL"
    for channel in "${CHANNELS[@]}"; do
        notify_slack/notify_slack.py \
            "Scheduled ${debug}job \`$CI_JOB_NAME\` *failed*. <$CI_JOB_URL|log>. Commit: <$CI_PROJECT_URL/-/commit/$CI_COMMIT_SHA|$CI_COMMIT_SHORT_SHA>." \
            --channel "$channel" || true
    done
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

# This only works if shellcheck is run from the repo root.
# shellcheck source=gitlab-ci/src/artifacts/collect_core_dumps.sh
. "${CI_PROJECT_DIR}"/gitlab-ci/src/artifacts/collect_core_dumps.sh

"${CI_PROJECT_DIR}"/gitlab-ci/src/log_metrics/log_metrics.py \
    build_time=$((end - $(cat "/tmp/job_start_date_$CI_JOB_ID"))) \
    start_time="$(cat "/tmp/job_start_iso_date_$CI_JOB_ID")" \
    HOSTNAME="$(hostname -f)"
