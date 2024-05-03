#!/bin/bash
set -xeuo pipefail

inputFilePath=".gitlab/CODEOWNERS"
outputFilePath=".github/CODEOWNERS"

# Uncomment once we are ready to use all teams on dfinity org, for now copy code owners for IDX
# Use sed to replace @dfinity-lab/teams with @dfinity-sandbox
# sed "s/@dfinity-lab\/teams/@dfinity/g" $inputFilePath > $outputFilePath

# for now, only include teams we want to test in the sandbox org
grep -E "^.*\/\s*@dfinity-lab/teams/idx$" $inputFilePath | sed "s/@dfinity-lab\/teams/@dfinity-sandbox/g" >$outputFilePath

git add $outputFilePath
# If there were changes commit them with the IDX GITLAB bot
if ! git diff --cached --quiet; then
    if [ "$CI_PIPELINE_SOURCE" = "merge_request_event" ] && [ "$CI_MERGE_REQUEST_EVENT_TYPE" != "merge_train" ]; then
        git remote add origin "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
        git remote set-url origin "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
        git config --global user.email "infra+gitlab-automation@dfinity.org"
        git config --global user.name "IDX GitLab Automation"
        git commit -m "Update github CODEOWNERS file"
        git push origin HEAD:"${CI_COMMIT_REF_NAME}"
        exit 0
    fi
    exit 1
fi
