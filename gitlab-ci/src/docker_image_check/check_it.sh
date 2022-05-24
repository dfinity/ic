#!/usr/bin/env bash

# Purpose: This script determines if all docker images referenced in CI yml files have a corresponding
# matching Dockerfile (sha1 of dockerfile must match the image name)
# If there is a mismatch the build / push script for docker images is run
MESSAGE="automated dockerfile hash fix in gitlab yml files"
REPO_ROOT="$(git rev-parse --show-toplevel)"

N="push" # by default we push the docker image to registry, and commits to github

# Flip N if we get --nopush argument
while [ $# -gt 0 ]; do
    case $1 in
        -n | --nopush) N="--nopush" ;;
    esac
    shift
done

check_for_git_message() {
    if git log --oneline -1 | grep -q -E "$MESSAGE"; then
        echo "Git log MESSAGE found = already tried this once, will not continue"
        return 1
    else
        echo "First time being run (not stuck in a loop), will continue"
        return 0
    fi
}

check_dockerfile_mismatch() {
    # check for dockerfile sha1 mismatch
    python3 "$REPO_ROOT"/gitlab-ci/src/docker_image_check/docker_image_check.py
    return $?
}

gitlab_login() {
    # log into gitlab in order to push images up
    # token used below allows us to push our image outside of the project
    echo "Logging into gitlab"
    docker login -u gitlab-ci-token -p "$GITLAB_API_TOKEN" registry.gitlab.com && echo "Logged into gitlab"
}

image_build() {
    echo "Building docker images with $N"
    echo -e "\e[0Ksection_start:$(date +%s):docker_build_script[collapsed=true]\r\e[0KClick here to see the docker_build_script"
    bash "$REPO_ROOT"/gitlab-ci/docker/docker-build-ci-image.sh "$N" # either 'push' or '--nopush'
    echo -e "\e[0Ksection_end:$(date +%s):docker_build_script\r\e[0K"
}

commit_updated_files() {
    # commit files updated by image_build with $MESSAGE
    # Candidates for updates: yml files, TAG file
    echo "Committing newly updated files (yml, TAG)"
    git commit -a -m "$MESSAGE"
}

push_to_github() {
    # push this branch with latest commit to gitlab
    # ssh credentials are used, and set up in the "before_script in CI yml"
    echo "Pushing this branch to gitlab"
    git remote add origin-gitlab "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
    git remote set-url origin-gitlab "https://gitlab-ci-token:${GITLAB_API_TOKEN}@gitlab.com/${CI_PROJECT_PATH}.git" || true
    git push --set-upstream origin-gitlab HEAD:"$CI_COMMIT_REF_NAME"
}

check_for_git_message
GIT_MESSAGE_VALUE=$?

check_dockerfile_mismatch
DOCKERFILES_STATUS=$?

set -eEuo pipefail # setting here to avoid use in above execution where we need to not exit with failures

if [ $DOCKERFILES_STATUS -eq 2 ]; then
    echo "Fatal error checking Dockerfile status. This is likely a bug. Bailing out."
    exit 1
fi

if [ $GIT_MESSAGE_VALUE -ne 0 ] && [ $DOCKERFILES_STATUS -ne 0 ]; then # mismatch, and 2nd time - in a forever loop
    echo "Mismatch in Dockerfile sha and Dockerfile image name, and unable to automatically correct, exiting."
    exit 1
elif [ $GIT_MESSAGE_VALUE -eq 0 ] && [ $DOCKERFILES_STATUS -ne 0 ]; then # mismatch, and 1st time trying to fix
    echo "Mismatch in Dockerfile sha and Dockerfile image name, will attempt to automatically correct situation"
    gitlab_login
    image_build
    git config --global user.email "infra+gitlab-automation@dfinity.org"
    git config --global user.name "IDX GitLab Automation"
    commit_updated_files

    if [ "$N" = "--nopush" ]; then
        echo "--nopush flag was set"
        exit 0
    else
        push_to_github
        exit 1
    fi
else
    echo "No mismatch with Dockerfile sha and Dockerfile image name, nothing to do, exiting."
fi

# extra comment - testing ci runs
