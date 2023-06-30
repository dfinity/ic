#!/usr/bin/env bash
set -eEuo pipefail

if [ -n "${IN_NIX_SHELL:-}" ]; then
    echo "Please do not run $0 inside of nix-shell." >&2
    exit 1
fi

if [ -e /run/.containerenv ]; then
    echo "Nested $0 is not supported!" >&2
    exit 1
fi

if ! which podman >/dev/null 2>&1; then
    echo "Podman missing...install it!" >&2
    exit 1
fi

usage() {
    cat <<EOF
Container Dev & Build Environment Script.

Usage: $0 -h | --help, -f | --full

    -f | --full  Use full container image (dfinity/ic-build-legacy)
    -h | --help  Print help

Script uses dfinity/ic-build image by default.
EOF
}

IMAGE="docker.io/dfinity/ic-build"
BUILD_ARGS=(--bazel)
CTR=0
while test $# -gt $CTR; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -f | --full)
            IMAGE="docker.io/dfinity/ic-build-legacy"
            BUILD_ARGS=()
            shift
            ;;
        *) let CTR=CTR+1 ;;
    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_TAG=$("$REPO_ROOT"/gitlab-ci/container/get-image-tag.sh)
IMAGE="$IMAGE:$IMAGE_TAG"
if ! sudo podman image exists $IMAGE; then
    if grep 'index.docker.io' $HOME/.docker/config.json >/dev/null 2>&1; then
        # copy credentials for root
        ROOT_HOME="$(getent passwd root | awk -F: '{print $6}')"
        sudo mkdir -p $ROOT_HOME/.docker
        sudo cp -f $HOME/.docker/config.json $ROOT_HOME/.docker/
        sudo podman login --authfile $ROOT_HOME/.docker/config.json docker.io
    fi
    if ! sudo podman pull $IMAGE; then
        # fallback to building the image
        docker() { sudo podman "$@" --network=host; }
        export -f docker
        "$REPO_ROOT"/gitlab-ci/container/build-image.sh "${BUILD_ARGS[@]}"
        unset -f docker
    fi
fi

WORKDIR="/ic"
USER=$(whoami)

PODMAN_RUN_ARGS=(
    -w "$WORKDIR"

    -u "$(id -u):$(id -g)"
    -e HOSTUSER="$USER"
    -e VERSION="${VERSION:-$(git rev-parse HEAD)}"
    --hostname=devenv-container
    --add-host devenv-container:127.0.0.1
    --entrypoint=
    --init
)

if podman version | grep -qE 'Version:\s+4.'; then
    PODMAN_RUN_ARGS+=(
        --hostuser="$USER"
    )
fi

PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"
    --mount type=bind,source="${HOME}",target="${HOME}"
    --mount type=bind,source="${HOME}/.cache",target="/home/ubuntu/.cache"
    --mount type=bind,source="${HOME}/.ssh",target="/home/ubuntu/.ssh"
    --mount type=bind,source="${HOME}/.aws",target="/home/ubuntu/.aws"
    --mount type=bind,source="/var/lib/containers",target="/var/lib/containers"
    --mount type=tmpfs,destination=/var/sysimage
)

if [ "$(id -u)" = "1000" ]; then
    if [ -e "${HOME}/.bash_history" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.bash_history",target="/home/ubuntu/.bash_history"
        )
    fi
    if [ -e "${HOME}/.local/share/fish" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.local/share/fish",target="/home/ubuntu/.local/share/fish"
        )
    fi
    if [ -e "${HOME}/.zsh_history" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.zsh_history",target="/home/ubuntu/.zsh_history"
        )
    fi

    USHELL=$(getent passwd "$USER" | cut -d : -f 7)
    if [[ "$USHELL" != *"/bash" ]] && [[ "$USHELL" != *"/zsh" ]] && [[ "$USHELL" != *"/fish" ]]; then
        USHELL=/usr/bin/bash
    fi
fi

if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -e "${SSH_AUTH_SOCK:-}" ]; then
    PODMAN_RUN_ARGS+=(
        -v "$SSH_AUTH_SOCK:/ssh-agent"
        -e SSH_AUTH_SOCK="/ssh-agent"
    )
else
    echo "No ssh-agent to forward."
fi

# make sure we have all bind-mounts
mkdir -p ~/.{aws,ssh,cache,local/share/fish} && touch ~/.{zsh,bash}_history

# privileged rootful podman is required due to requirements of IC-OS guest build
# additionally, we need to use hosts's cgroups and network
if [ $# -eq 0 ]; then
    set -x
    sudo podman run --pids-limit=-1 -it --rm --privileged --network=host --cgroupns=host \
        "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" ${USHELL:-/usr/bin/bash}
    set +x
else
    set -x
    sudo podman run --pids-limit=-1 -it --rm --privileged --network=host --cgroupns=host \
        "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" "$@"
    set +x
fi
