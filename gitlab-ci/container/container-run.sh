#!/usr/bin/env bash
set -eEuo pipefail

if [ -e /run/.containerenv ]; then
    echo "Nested $0 is not supported!" >&2
    exit 1
fi

if ! which podman >/dev/null 2>&1; then
    echo "Podman missing...install it!" >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_TAG="$(cat $REPO_ROOT/gitlab-ci/container/TAG)"
IMAGE="docker.io/dfinity/ic-build-bazel:$IMAGE_TAG"
if ! sudo podman image exists $IMAGE; then
    if grep 'index.docker.io' $HOME/.docker/config.json >/dev/null 2>&1; then
        # copy credentials for root
        ROOT_HOME="$(getent passwd root | awk -F: '{print $6}')"
        sudo mkdir -p $ROOT_HOME/.docker
        sudo cp -f $HOME/.docker/config.json $ROOT_HOME/.docker/
        sudo podman login --authfile $ROOT_HOME/.docker/config.json docker.io
    fi
    if ! sudo podman pull $IMAGE; then
        # failback to latest in case $IMAGE_TAG was not yet pushed to dockerhub
        IMAGE="docker.io/dfinity/ic-build-bazel:latest"
        sudo podman pull $IMAGE
    fi
fi

WORKDIR="/ic"
USER=$(whoami)

PODMAN_RUN_ARGS=(
    -w "$WORKDIR"

    -u "$(id -u):$(id -g)"
    --env PATH=/ic/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    --env HOME="/home/$USER"
    --hostname=devenv-container
    --entrypoint=

    -e VERSION="${VERSION:-$(git rev-parse HEAD)}"
    -e CI_COMMIT_REF_PROTECTED="${CI_COMMIT_REF_PROTECTED:-true}"
)

if podman version | grep -qE 'Version:\s+4.'; then
    PODMAN_RUN_ARGS+=(
        --hostuser="$USER"
    )
fi

PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"
    --mount type=bind,source="/var/lib/containers",target="/var/lib/containers"
    --mount type=bind,source="${HOME}",target="${HOME}"
    --mount type=tmpfs,destination=/var/sysimage
)

if [ -n "${SSH_AUTH_SOCK:-}" ]; then
    PODMAN_RUN_ARGS+=(
        -v "$SSH_AUTH_SOCK:/ssh-agent"
        -e SSH_AUTH_SOCK="/ssh-agent"
    )
fi

# privileged rootful podman is required due to requirements of IC-OS guest build
# additionally, we need to use hosts's cgroups and network
if [ $# -eq 0 ]; then
    set -x
    sudo podman run -it --rm --privileged --network=host --cgroupns=host \
        "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" bash --rcfile /etc/bash.bashrc
    set +x
else
    set -x
    sudo podman run -it --rm --privileged --network=host --cgroupns=host \
        "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" "$@"
    set +x
fi
