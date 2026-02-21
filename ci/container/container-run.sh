#!/usr/bin/env bash
set -eEuo pipefail

## This script only supports podman as container runtime

eprintln() {
    echo "$@" >&2
}

if [ -n "${IN_NIX_SHELL:-}" ]; then
    eprintln "Please do not run $0 inside of nix-shell."
    exit 1
fi

if [ -e /run/.containerenv ]; then
    eprintln "Nested $0 is not supported."
    exit 1
fi

if ! which podman >/dev/null 2>&1; then
    eprintln "Podman needs to be installed to run this script."
    exit 1
fi

# Verify podman is reachable/responding
if ! podman info >/dev/null 2>&1; then
    eprintln "Podman found but not responding (daemon/service not running or not reachable)."
    exit 1
fi

usage() {
    cat <<EOF
Usage: $0 -h | --help, -c <dir> | --cache-dir <dir>

    -c | --cache-dir <dir>  Bind-mount custom cache dir instead of '~/.cache'
    -r | --rebuild          Rebuild the container image
    -i | --image <image>    ic-build or ic-dev (default: ic-dev)
    -h | --help             Print help

If USHELL is not set, the default shell (/usr/bin/bash) will be started inside the container.
To run a different shell or command, pass it as arguments, e.g.:

    $0 /usr/bin/zsh
    $0 bash -l

EOF
}

REBUILD_IMAGE=false
IMAGE_NAME="ic-dev"

CTR=0
while test $# -gt $CTR; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -f | --full) eprintln "The legacy image has been deprecated, --full is not an option anymore." && exit 0 ;;
        -r | --rebuild)
            REBUILD_IMAGE=true
            shift
            ;;
        -i | --image)
            shift
            if [ $# -eq 0 ]; then
                echo "Error: --image requires an argument" >&2
                usage >&2
                exit 1
            fi
            IMAGE_NAME="$1"
            shift
            ;;
        -c | --cache-dir)
            if [[ $# -gt "$CTR + 1" ]]; then
                if [ ! -d "$2" ]; then
                    eprintln "$2 is not a directory! Create it and try again."
                    usage && exit 1
                fi
                CACHE_DIR="$2"
                eprintln "Bind-mounting $CACHE_DIR as cache directory."
            else
                eprintln "Missing argument for -c | --cache-dir!"
                usage && exit 1
            fi
            shift
            shift
            ;;
        *) let CTR=CTR+1 ;;
    esac
done

# option to pass in another shell if desired
if [ $# -eq 0 ]; then
    cmd=("${USHELL:-/usr/bin/bash}")
else
    cmd=("$@")
fi
echo "Using ${cmd[*]} as run command."

# Detect environment
if [ -d /var/lib/cloud/instance ] && findmnt /hoststorage >/dev/null; then
    echo "Detected Devenv environment."
    DEVENV=true
else
    DEVENV=false
fi

if [ "$DEVENV" = true ]; then
    echo "Using hoststorage for podman root."
    CONTAINER_CMD=(sudo podman --root /hoststorage/podman-root)
else
    CONTAINER_CMD=(sudo podman)
fi

echo "Using container command: ${CONTAINER_CMD[*]}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)
IMAGE="ghcr.io/dfinity/$IMAGE_NAME:$IMAGE_TAG"

if [ $REBUILD_IMAGE = true ]; then
    "$REPO_ROOT"/ci/container/build-image.sh --image "$IMAGE_NAME"
elif ! "${CONTAINER_CMD[@]}" image exists $IMAGE; then
    if ! "${CONTAINER_CMD[@]}" pull $IMAGE; then
        "$REPO_ROOT"/ci/container/build-image.sh --image "$IMAGE_NAME"
    fi
fi

if [ "$DEVENV" = true ]; then
    eprintln "Purging non-relevant container images"
    "${CONTAINER_CMD[@]}" image prune -a -f --filter "reference!=$IMAGE"
fi

WORKDIR="/ic"
HOST_USER=$(whoami)
HOST_UID=$(id -u)
HOST_GID=$(id -g)
CONTAINER_UID="1000"
CONTAINER_GID="1000"

PODMAN_RUN_ARGS=(
    -w "$WORKDIR"

    -u "$HOST_UID:$HOST_GID"
    -e HOSTUSER="$HOST_USER"
    -e HOSTHOSTNAME="$HOSTNAME"
    -e VERSION="${VERSION:-$(git rev-parse HEAD)}"
    -e TERM
    -e LANG=C.UTF-8
    -e CARGO_TERM_COLOR
    --hostname=devenv-container
    --add-host devenv-container:127.0.0.1
    --entrypoint=
    --init
    --pull=missing
)

PODMAN_RUN_ARGS+=(--hostuser="$HOST_USER")

if [ "$HOST_UID" = "1000" ]; then
    CTR_HOME="/home/ubuntu"
else
    CTR_HOME="/ic"
fi

CACHE_DIR="${CACHE_DIR:-${HOME}/.cache}"

ZIG_CACHE="${CACHE_DIR}/zig-cache"
mkdir -p "${ZIG_CACHE}"

ICT_TESTNETS_DIR="/tmp/ict_testnets"
mkdir -p "${ICT_TESTNETS_DIR}"

# make sure we have all bind-mounts
mkdir -p ~/.{aws,ssh,cache}

PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"
    --mount type=bind,source="${CACHE_DIR:-${HOME}/.cache}",target="${CTR_HOME}/.cache"
    --mount type=bind,source="${ZIG_CACHE}",target="/tmp/zig-cache"
    --mount type=bind,source="${ICT_TESTNETS_DIR}",target="${ICT_TESTNETS_DIR}"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh"
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws"
    --mount type=tmpfs,target="${CTR_HOME}/.local/share/containers"
)

if [ -e "${HOME}/.gitconfig" ]; then
    PODMAN_RUN_ARGS+=(
        --mount type=bind,source="${HOME}/.gitconfig",target="${CTR_HOME}/.gitconfig"
    )
fi

if [ -e "${HOME}/.bash_history" ]; then
    PODMAN_RUN_ARGS+=(
        --mount type=bind,source="${HOME}/.bash_history",target="${CTR_HOME}/.bash_history"
    )

fi
if [ -e "${HOME}/.local/share/fish" ]; then
    PODMAN_RUN_ARGS+=(
        --mount type=bind,source="${HOME}/.local/share/fish",target="${CTR_HOME}/.local/share/fish"
    )
fi
if [ -e "${HOME}/.zsh_history" ]; then
    PODMAN_RUN_ARGS+=(
        --mount type=bind,source="${HOME}/.zsh_history",target="${CTR_HOME}/.zsh_history"
    )
fi

if findmnt /hoststorage >/dev/null; then
    # use host's storage for cargo target
    # * shared with VSCode's devcontainer, see .devcontainer/devcontainer.json
    # this configuration improves performance of rust-analyzer
    if [ ! -d /hoststorage/cache/cargo ]; then
        sudo mkdir -p /hoststorage/cache/cargo
        sudo chown -R $CONTAINER_UID:$CONTAINER_GID /hoststorage/cache/cargo
    fi
    PODMAN_RUN_ARGS+=(
        --mount type=bind,source="/hoststorage/cache/cargo",target="/ic/target"
    )
fi

if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -e "${SSH_AUTH_SOCK:-}" ]; then
    PODMAN_RUN_ARGS+=(
        -v "$SSH_AUTH_SOCK:/ssh-agent"
        -e SSH_AUTH_SOCK="/ssh-agent"
    )
else
    eprintln "No ssh-agent to forward."
fi

# Omit -t if not a tty.
# Also shut up logging, because podman will by default log
# every byte of standard output to the journal, and that
# destroys the journal + wastes enormous amounts of CPU.
# I witnessed journald and syslog peg 2 cores of my devenv
# when running a simple cat /path/to/file.
if tty >/dev/null 2>&1; then
    tty_arg=-t
else
    tty_arg=
fi

# Privileged rootful podman is required due to requirements of IC-OS guest build;
# additionally, we need to use hosts's cgroups and network.
OTHER_ARGS=(--pids-limit=-1 -i $tty_arg --log-driver=none --rm --privileged --network=host --cgroupns=host)

if [ -f "$HOME/.container-run.conf" ]; then
    # conf file with user's custom PODMAN_RUN_USR_ARGS
    # This file is very handy but is a source of non-hermeticity, and issues
    # related to it are hard to track down so we print a bold yellow message
    # when it is in use.
    tput -T xterm setaf 3
    tput -T xterm bold
    eprintln "Sourcing user's ~/.container-run.conf"
    tput -T xterm sgr0
    source "$HOME/.container-run.conf"
    PODMAN_RUN_ARGS+=("${PODMAN_RUN_USR_ARGS[@]}")
fi

set -x
exec "${CONTAINER_CMD[@]}" run "${OTHER_ARGS[@]}" "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" "${cmd[@]}"
