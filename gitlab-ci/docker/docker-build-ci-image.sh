#!/usr/bin/env bash
# Prepare the Docker container image, and then upload it to registry.gitlab.com

set -eEuo pipefail

REPO_ROOT="$(
    cd "$(dirname "$0")"
    git rev-parse --show-toplevel
)"
cd "$REPO_ROOT"

VERSION=$(cat "$REPO_ROOT/gitlab-ci/docker/TAG")
NEWVERSION="$(date +"%Y-%m-%d")-$(git rev-parse --short HEAD)"

find . -type f \( -name "*.yml" -o -name "TAG" \) -exec sed -i -e "s/$VERSION/$NEWVERSION/g" '{}' +

"$REPO_ROOT/gitlab-ci/docker/docker-build-local-image.sh"

# Push the new image to registry.gitlab.com after building it
if grep -q "https://index.docker.io" ~/.docker/config.json; then
    docker push dfinity/ic-build:$NEWVERSION
    docker push dfinity/ic-build:latest
    docker push dfinity/ic-build-nix:$NEWVERSION
    docker push dfinity/ic-build-nix:latest
else
    echo "WARNING: Not logged in to Docker Hub, pushing to Docker Hub skipped"
fi

if grep -q "registry.gitlab.com" ~/.docker/config.json; then
    docker push registry.gitlab.com/dfinity-lab/dfinity/ic-build:$NEWVERSION
    docker push registry.gitlab.com/dfinity-lab/core/labrat/ic-build:$NEWVERSION
    docker push registry.gitlab.com/dfinity-lab/dfinity/ic-build-nix:$NEWVERSION
    docker push registry.gitlab.com/dfinity-lab/core/labrat/ic-build-nix:$NEWVERSION
else
    echo "WARNING: Not logged in to registry.gitlab.com, pushing to registry.gitlab.com skipped"
fi
