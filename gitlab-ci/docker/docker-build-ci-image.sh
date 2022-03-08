#!/usr/bin/env bash
# Prepare the Docker container image, and then upload it to registry.gitlab.com

set -eEuo pipefail

NOPUSH=

while [ $# -gt 0 ]; do
    case $1 in
        -n | --nopush | --no-push) NOPUSH=1 ;;
    esac
    shift
done

REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"
cd "$REPO_ROOT"

VERSION=$(cat "$REPO_ROOT/gitlab-ci/docker/TAG")
NEWVERSION="$(date +"%Y-%m-%d")-$(git rev-parse --short HEAD)"

SHA1ICBUILD=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile)
SHA1ICBUILDNIX=$("$REPO_ROOT/gitlab-ci/src/docker_image_check/docker_sha.py" Dockerfile.withnix)

find . -type f \( -name "TAG" \) -exec sed --in-place -e "s/$VERSION/$NEWVERSION/g" '{}' +
find . -type f \( -name "*.yml" \) -exec sed --in-place \
    -e "s/ic-build-nix:$VERSION.*$/ic-build-nix:$NEWVERSION-$SHA1ICBUILDNIX\"/" \
    -e "s/ic-build:$VERSION.*$/ic-build:$NEWVERSION-$SHA1ICBUILD\"/" \
    '{}' +

"$REPO_ROOT/gitlab-ci/docker/docker-build-local-image.sh" --nix

if [ -n "$NOPUSH" ]; then
    echo >&2 "--no-push is set, exiting now"
    exit 0
fi

if grep -q "registry.gitlab.com" ~/.docker/config.json; then
    docker push registry.gitlab.com/dfinity-lab/core/docker/ic-build:"$NEWVERSION"-"$SHA1ICBUILD"
    docker push registry.gitlab.com/dfinity-lab/core/docker/ic-build-nix:"$NEWVERSION"-"$SHA1ICBUILDNIX"
else
    echo "WARNING: Not logged in to registry.gitlab.com, pushing to registry.gitlab.com skipped"
fi

# push to dockerhub as well
docker login -u "$DOCKER_HUB_USER" -p "$DOCKER_HUB_PASSWORD"
docker push dfinity/ic-build:"$NEWVERSION"
docker push dfinity/ic-build:latest
docker push dfinity/ic-build-nix:"$NEWVERSION"
docker push dfinity/ic-build-nix:latest
