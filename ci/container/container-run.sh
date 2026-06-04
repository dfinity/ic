#!/usr/bin/env bash
set -eEuo pipefail

## This script only supports podman as container runtime

eprintln() {
    echo "$@" >&2
}

# Print a yellow, bold message
warn() {
    tput -T xterm setaf 3 >&2
    tput -T xterm bold >&2
    eprintln "$@"
    tput -T xterm sgr0 >&2
}

usage() {
    cat <<EOF
Usage: $0 -h | --help, -c <dir> | --cache-dir <dir>

    -c | --cache-dir <dir>  Bind-mount custom cache dir instead of '~/.cache'
    -i | --image <image>    ic-build or ic-dev (default: ic-dev)
    -h | --help             Print help

If USHELL is not set, the default shell (/usr/bin/bash) will be started inside the container.
To run a different shell or command, pass it as arguments, e.g.:

    $0 /usr/bin/zsh
    $0 bash -l

EOF
}

if [ -e /run/.containerenv ]; then
    eprintln "Nested $0 is not supported."
    exit 1
fi

IMAGE_NAME="ic-dev"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -i | --image)
            IMAGE_NAME="${2:?missing value for "$1"}"
            shift # shift past flag and value
            shift
            ;;
        -c | --cache-dir)
            CACHE_DIR="${2:?missing value for "$1"}"
            shift # shift past flag and value
            shift
            ;;
        *)
            # found unknown argument; assume the rest is a user-supplied command to run
            cmd=("$@")
            break
            ;;
    esac
done

if [ -z "${cmd:-}" ]; then
    # if no command is specified, create an shell
    if [ -z "${USHELL:-}" ] || [ "$USHELL" == "bash" ]; then
        # bit of a hack: we source the completion by passing it as an rcfile.
        # The completion itself requires `.bazelversion` to exist.
        # We avoid generating the completion in the container _build_ so that
        # the container itself does not depend on the bazel version.
        cmd=("/usr/bin/bash" -c "exec bash --rcfile <(echo 'source ~/.bashrc'; bazel completion bash)")
    else
        cmd=("$USHELL")
    fi
fi
eprintln "Using '${cmd[*]}' as run command."

# Detect environment
if [ -d /var/lib/cloud/instance ] && findmnt /hoststorage >/dev/null; then
    eprintln "Detected Devenv environment."
    DEVENV=true
else
    DEVENV=false
fi

if [ "$DEVENV" = true ]; then
    CONTAINER_CMD=(sudo podman --root /hoststorage/podman-root)
else
    CONTAINER_CMD=(sudo podman)
fi

eprintln "Using container command: '${CONTAINER_CMD[*]}'"

# Verify podman is reachable/responding
if ! "${CONTAINER_CMD[@]}" info >/dev/null 2>&1; then
    warn "No container runtime, check the command is installed and working:"
    warn "> ${CONTAINER_CMD[*]}"
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)
IMAGE="ghcr.io/dfinity/$IMAGE_NAME:$IMAGE_TAG"

if ! "${CONTAINER_CMD[@]}" image exists "$IMAGE"; then
    if ! "${CONTAINER_CMD[@]}" pull "$IMAGE"; then
        "$REPO_ROOT"/ci/container/build-image.sh --image "$IMAGE_NAME"
    fi
fi

if [ "$DEVENV" = true ]; then
    # on the devenv we issue a warning if the images start taking up a lot of space.
    # Podman does not have a dedicated layer cache like docker, so we avoid nuking dangling/unused images unless space becomes a concern;
    # this allows new image builds to benefit from cached layers.
    # We only issue a warning so that the user can GC when it's most convenient.
    MAX_GB=20
    images_rawsize=$("${CONTAINER_CMD[@]}" system df --format json | jq -cMr '.[]|select(.Type == "Images")|.RawSize')
    if ((images_rawsize > MAX_GB * 10 ** 9)); then
        warn "Container images take up more than ${MAX_GB}GB. You can reclaim space by clearing the container image cache (will cause a rebuild):"
        warn "> ${CONTAINER_CMD[*]} image prune --all --force --filter containers=false"
    fi
fi

WORKDIR="/ic"

# the docker image creates two users: ubuntu (1000) and buildifier (1001). Here we ensure the correct home is used.
HOST_UID="$(id -u)"
if [ "$HOST_UID" = "1000" ]; then
    CTR_USER="ubuntu"
    CTR_HOME="/home/ubuntu"
elif [ "$HOST_UID" = "1001" ]; then
    CTR_USER="buildifier"
    CTR_HOME="/home/buildifier"
else
    warn "User ID '$HOST_UID' does not have a corresponding container user, using root"
    CTR_USER="root"
    CTR_HOME="/root"
fi

eprintln "Using container user '$CTR_USER'"
# cache directory in the container
CTR_CACHE_DIR="$CTR_HOME/.cache"

# cache directory on the host
# NOTE: in devenvs, ~/.cache is `/hoststorage/cache`
CACHE_DIR="${CACHE_DIR:-${HOME}/.cache}"

ZIG_CACHE="${CACHE_DIR}/zig-cache"
mkdir -p "${ZIG_CACHE}"

ICT_TESTNETS_DIR="/tmp/ict_testnets"
mkdir -p "${ICT_TESTNETS_DIR}"

# make sure we have all bind-mounts
# ~/.aws, ~/.ssh: credentials forwarded to the container
# ~/.cache: used as cache persisted across containers (cargo, etc)
# ~/.claude: persisted claude settings
mkdir -p ~/.{aws,ssh,cache,claude}

PODMAN_RUN_ARGS=(
    -w "$WORKDIR"
    --rm              # remove container after it ran
    --log-driver=none # by default podman logs all of stdout to the journal which is resource-consuming and wasteful

    --user "$CTR_USER:$CTR_USER" # user, assuming it has a corresponding group

    # metadata used by system tests for logging
    -e HOSTUSER="$(whoami)"
    -e HOSTHOSTNAME="$HOSTNAME"

    # colored output for cargo & friends
    # (forward host values)
    -e TERM
    -e LANG=C.UTF-8
    -e CARGO_TERM_COLOR

    --hostname=devenv-container
    --add-host devenv-container:127.0.0.1

    # ensures processes are reaped correctly
    --init

    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"     # mount the local repo checkout
    --mount type=bind,source="${ZIG_CACHE}",target="/tmp/zig-cache" # C toolchain cache, persisted to speed up rebuilds
    --mount type=bind,source="${ICT_TESTNETS_DIR}",target="${ICT_TESTNETS_DIR}"
    --mount type=bind,source="${CACHE_DIR}",target="${CTR_CACHE_DIR}" # persisted root for caches (cargo, etc)

    # mount credentials & settings
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh"
    --mount type=bind,source="${HOME}/.claude",target="${CTR_HOME}/.claude"

    --mount type=tmpfs,target="/tmp/containers" # expected by ic-os build

    # Privileged rootful podman is required due to requirements of IC-OS guest build;
    # additionally, we need to use hosts's cgroups and network.
    --pids-limit=-1 --privileged --network=host --cgroupns=host
)

# In the devenv, inject some extra files into the container for convenience
if [ "$DEVENV" = true ]; then
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

    # persist cargo target across containers
    # * shared with VSCode's devcontainer, see .devcontainer/devcontainer.json
    # this configuration improves performance of rust-analyzer
    PODMAN_RUN_ARGS+=(
        -e CARGO_TARGET_DIR="$CTR_CACHE_DIR/cargo"
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

# if a user is attached, make it interactive and create tty
if tty >/dev/null 2>&1; then
    PODMAN_RUN_ARGS+=(-i -t)
fi

if [ -f "$HOME/.container-run.conf" ]; then
    # conf file with user's custom PODMAN_RUN_USR_ARGS
    # This file is very handy but is a source of non-hermeticity, and issues
    # related to it are hard to track down so we print a bold yellow message
    # when it is in use.
    warn "Sourcing user's ~/.container-run.conf"
    source "$HOME/.container-run.conf"
    PODMAN_RUN_ARGS+=("${PODMAN_RUN_USR_ARGS[@]}")
fi

set -x
exec "${CONTAINER_CMD[@]}" run "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" "${cmd[@]}"
