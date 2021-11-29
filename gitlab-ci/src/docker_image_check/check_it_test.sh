#!/usr/bin/env bash
# The purpose of this test is to ensure the codepath for automatically building new docker images is safe and future-proof

set -eEuo pipefail
tmp_dir=$(mktemp -d -t ci-XXXXXXXXXX)
# echo "tmp_dir: $tmp_dir"
cp -R "$(git rev-parse --show-toplevel)" "$tmp_dir"

cd "$tmp_dir/$CI_PROJECT_NAME"
# echo $(ls)

git config --global user.email "infra+gitlab-automation@dfinity.org"
git config --global user.name "IDX GitLab Automation"
git commit -a -m "blank commit" --allow-empty # prevents check_it.sh from bailing
echo "# force-rebuild 1" >>gitlab-ci/docker/Dockerfile

# Added the --nopush flag to make the script not push the docker image to GitLab registry or the commit to GitLab

echo "RUNNING FIRST CHECK_IT_TEST DOCKER BUILD WITH --NOPUSH"
./gitlab-ci/src/docker_image_check/check_it.sh --nopush

git log --oneline -1 | grep -q -E "automated dockerfile hash fix in gitlab yml files"

echo "# force-rebuild 2" >>gitlab-ci/docker/Dockerfile

echo "RUNNING SECOND CHECK_IT_TEST DOCKER BUILD WITH --NOPUSH"
./gitlab-ci/src/docker_image_check/check_it.sh --nopush && exit 1 || exit 0
