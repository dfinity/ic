#!/bin/bash
set -xeuo pipefail

inputFilePath=".gitlab/CODEOWNERS"
outputFilePath=".github/CODEOWNERS"

declare -A teamsMap=(
    ["@dfinity-lab/teams/DRE"]="@dfinity/dre"
    ["@dfinity-lab/teams/boundarynode-team"]="@dfinity/boundary-node"
    ["@dfinity-lab/teams/consensus-owners"]="@dfinity/consensus"
    ["@dfinity-lab/teams/cross-chain-team"]="@dfinity/cross-chain-team"
    ["@dfinity-lab/teams/crypto-owners"]="@dfinity/crypto-team"
    ["@dfinity-lab/teams/execution-owners"]="@dfinity/execution"
    ["@dfinity-lab/teams/execution-team"]="@dfinity/execution"
    ["@dfinity-lab/teams/financial-integrations"]="@dfinity/finint"
    ["@dfinity-lab/teams/ic-support"]="@dfinity/ic-support"
    ["@dfinity-lab/teams/ic-testing-verification"]="@dfinity/ic-testing-verification"
    ["@dfinity-lab/teams/idx"]="@dfinity/idx"
    ["@dfinity-lab/teams/infrasec"]="@dfinity/infrasec"
    ["@dfinity-lab/teams/interface-owners"]="@dfinity/ic-interface-owners"
    ["@dfinity-lab/teams/message-routing-owners"]="@dfinity/ic-message-routing-owners"
    ["@dfinity-lab/teams/networking-team"]="@dfinity/networking"
    ["@dfinity-lab/teams/nns-team"]="@dfinity/nns-team"
    ["@dfinity-lab/teams/node-team"]="@dfinity/node"
    ["@dfinity-lab/teams/owners-owners"]="@dfinity/ic-owners-owners"
    ["@dfinity-lab/teams/platform-operations"]="@dfinity/platform-operations"
    ["@dfinity-lab/teams/prodsec"]="@dfinity/product-security"
    ["@dfinity-lab/teams/runtime-owners"]="@dfinity/runtime"
    ["@dfinity-lab/teams/sdk-team"]="@dfinity/sdk"
    ["@dfinity-lab/teams/utopia"]="@dfinity/utopia"
    ["@dfinity-lab/teams/ghost"]=""
)

cp $inputFilePath $outputFilePath

for i in "${!teamsMap[@]}"; do
    sed -i "s#$i#${teamsMap[$i]}#g" $outputFilePath
done

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
