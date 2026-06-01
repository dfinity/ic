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
    -i | --image <image>    ic-build or ic-dev (default: ic-dev)
    -h | --help             Print help

If USHELL is not set, the default shell (/usr/bin/bash) will be started inside the container.
To run a different shell or command, pass it as arguments, e.g.:

    $0 /usr/bin/zsh
    $0 bash -l

EOF
}

IMAGE_NAME="ic-dev"

CTR=0
while test $# -gt $CTR; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
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

if [ $# -eq 0 ]; then
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

if ! "${CONTAINER_CMD[@]}" image exists $IMAGE; then
    if ! "${CONTAINER_CMD[@]}" pull $IMAGE; then
        "$REPO_ROOT"/ci/container/build-image.sh --image "$IMAGE_NAME"
    fi
fi

if [ "$DEVENV" = true ]; then
    # on the devenv we issue a warning if the images start taking up a lot of space.
    # Podman does not have a dedicated layer cache like docker, so we avoid nuking dangling/unused images unless space becomes a concern;
    # this allows new image builds to benefit from cached layers.
    # We only issue a warning so that the user can GC when it's most convenient.
    MAX_GB=20
    images_rawsize=$(${CONTAINER_CMD[@]} system df --format json | jq -cMr '.[]|select(.Type == "Images")|.RawSize')
    if (($images_rawsize > $MAX_GB * 10 ** 9)); then
        warn "Container images take up more than ${MAX_GB}GB. You can reclaim space by clearing the container image cache (will cause a rebuild):"
        warn "> ${CONTAINER_CMD[@]} image prune --all --force --filter containers=false"
    fi
fi

WORKDIR="/ic"
USER=$(whoami)

PODMAN_RUN_ARGS=(
    -w "$WORKDIR"
    --rm              # remove container after it ran
    --log-driver=none # by default podman logs all of stdout to the journal which is resource-consuming and wasteful

    -u "ubuntu:ubuntu"
    -e HOSTUSER="$USER"
    -e HOSTHOSTNAME="$HOSTNAME"
    -e VERSION="${VERSION:-$(git rev-parse HEAD)}"
    -e TERM
    -e LANG=C.UTF-8
    -e CARGO_TERM_COLOR
    --hostname=devenv-container
    --add-host devenv-container:127.0.0.1
    --entrypoint=
    --init
)

PODMAN_RUN_ARGS+=(--hostuser="$USER")

if [ "$(id -u)" = "1000" ]; then
    CTR_HOME="/home/ubuntu"
else
    CTR_HOME="/ic"
fi

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

PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"
    --mount type=bind,source="${ZIG_CACHE}",target="/tmp/zig-cache"
    --mount type=bind,source="${ICT_TESTNETS_DIR}",target="${ICT_TESTNETS_DIR}"
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh"
    --mount type=bind,source="${CACHE_DIR}",target="${CTR_HOME}/.cache"
    --mount type=bind,source="${HOME}/.claude",target="${CTR_HOME}/.claude"
    --mount type=tmpfs,target="/tmp/containers"
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

    # use hoststorage for cargo target
    # * shared with VSCode's devcontainer, see .devcontainer/devcontainer.json
    # this configuration improves performance of rust-analyzer
    CARGO_TARGET_DIR="$CACHE_DIR/cargo"
    mkdir -p "$CARGO_TARGET_DIR"

    PODMAN_RUN_ARGS+=(
        --mount type=bind,source="$CARGO_TARGET_DIR",target="/ic/target"
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

# Privileged rootful podman is required due to requirements of IC-OS guest build;
# additionally, we need to use hosts's cgroups and network.
PODMAN_RUN_ARGS+=(--pids-limit=-1 --privileged --network=host --cgroupns=host)

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
exec "${CONTAINER_CMD[@]}" run "${PODMAN_RUN_ARGS[@]}" -w "$WORKDIR" "$IMAGE" "${cmd[@]}"
