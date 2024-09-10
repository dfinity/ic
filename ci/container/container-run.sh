#!/usr/bin/env bash
set -eEuo pipefail

if [ -n "${IN_NIX_SHELL:-}" ]; then
    echo "Please do not run $0 inside of nix-shell." >&2
    exit 1
fi

if [ -e /run/.containerenv ]; then
    echo "Nested $0 is not supported." >&2
    exit 1
fi

if ! which podman >/dev/null 2>&1; then
    echo "Podman missing...install it." >&2
    exit 1
fi

usage() {
    cat <<EOF
Usage: $0 -h | --help, -c <dir> | --cache-dir <dir>

    -c | --cache-dir <dir>  Bind-mount custom cache dir instead of '~/.cache'
    -h | --help             Print help

Script uses dfinity/ic-build image by default.
EOF
}

if findmnt /hoststorage >/dev/null; then
    PODMAN_ARGS=(--root /hoststorage/podman-root)
else
    PODMAN_ARGS=()
fi

IMAGE="ghcr.io/dfinity/ic-build"
BUILD_ARGS=(--bazel)
CTR=0
while test $# -gt $CTR; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -f | --full) echo "The legacy image has been deprecated, --full is not an option anymore." && exit 0 ;;
        -c | --cache-dir)
            if [[ $# -gt "$CTR + 1" ]]; then
                if [ ! -d "$2" ]; then
                    echo "$2 is not a directory! Create it and try again."
                    usage && exit 1
                fi
                CACHE_DIR="$2"
                echo "Bind-mounting $CACHE_DIR as cache directory."
            else
                echo "Missing argument for -c | --cache-dir!"
                usage && exit 1
            fi
            shift
            shift
            ;;
        *) let CTR=CTR+1 ;;
    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)
IMAGE="$IMAGE:$IMAGE_TAG"
if ! sudo podman "${PODMAN_ARGS[@]}" image exists $IMAGE; then
    if ! sudo podman "${PODMAN_ARGS[@]}" pull $IMAGE; then
        # fallback to building the image
        docker() { sudo podman "${PODMAN_ARGS[@]}" "$@" --network=host; }
        export -f docker
        "$REPO_ROOT"/ci/container/build-image.sh "${BUILD_ARGS[@]}"
        unset -f docker
    fi
fi

if findmnt /hoststorage >/dev/null; then
    echo "Purging non-relevant container images"
    sudo podman "${PODMAN_ARGS[@]}" image prune -a -f --filter "reference!=$IMAGE"
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
    --pull=missing
)

if podman version | grep -qE 'Version:\s+4.'; then
    PODMAN_RUN_ARGS+=(
        --hostuser="$USER"
    )
fi

if [ "$(id -u)" = "1000" ]; then
    CTR_HOME="/home/ubuntu"
else
    CTR_HOME="/ic"
fi

PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"
    --mount type=bind,source="${HOME}",target="${HOME}"
    --mount type=bind,source="${CACHE_DIR:-${HOME}/.cache}",target="${CTR_HOME}/.cache"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh"
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws"
    --mount type=bind,source="/var/lib/containers",target="/var/lib/containers"
    --mount type=bind,source="/tmp",target="/tmp"
    --mount type=tmpfs,destination=/var/sysimage
)

if [ "$(id -u)" = "1000" ]; then
    if [ -e "${HOME}/.gitconfig" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.gitconfig",target="/home/ubuntu/.gitconfig"
        )
    fi

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

PODMAN_RUN_USR_ARGS=()
if [ -f "$HOME/.container-run.conf" ]; then
    # conf file with user's custom PODMAN_RUN_USR_ARGS
    echo "Sourcing user's ~/.container-run.conf"
    source "$HOME/.container-run.conf"
fi

# privileged rootful podman is required due to requirements of IC-OS guest build
# additionally, we need to use hosts's cgroups and network
if [ $# -eq 0 ]; then
    set -x
    sudo podman "${PODMAN_ARGS[@]}" run --pids-limit=-1 -it --rm --privileged --network=host --cgroupns=host \
        "${PODMAN_RUN_ARGS[@]}" ${PODMAN_RUN_USR_ARGS[@]} -w "$WORKDIR" \
        "$IMAGE" ${USHELL:-/usr/bin/bash}
    set +x
else
    set -x
    sudo podman "${PODMAN_ARGS[@]}" run --pids-limit=-1 -it --rm --privileged --network=host --cgroupns=host \
        "${PODMAN_RUN_ARGS[@]}" "${PODMAN_RUN_USR_ARGS[@]}" -w "$WORKDIR" \
        "$IMAGE" "$@"
    set +x
fi
