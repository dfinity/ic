#!/usr/bin/env bash
set -eEuo pipefail

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
    eprintln "Podman missing...install it."
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
CTR=0
while test $# -gt $CTR; do
    case "$1" in
        -h | --help) usage && exit 0 ;;
        -f | --full) eprintln "The legacy image has been deprecated, --full is not an option anymore." && exit 0 ;;
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

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_TAG=$("$REPO_ROOT"/ci/container/get-image-tag.sh)
IMAGE="$IMAGE:$IMAGE_TAG"
if ! sudo podman "${PODMAN_ARGS[@]}" image exists $IMAGE; then
    if ! sudo podman "${PODMAN_ARGS[@]}" pull $IMAGE; then
        # fallback to building the image
        docker() {
            # Preserve "${PODMAN_ARGS[@]}" in the exported function by passing
            # them through a single variable, and unpacking them here.
            PODMAN_ARGS=(${PODMAN_ARGS})
            sudo podman "${PODMAN_ARGS[@]}" "$@" --network=host
        }
        export -f docker
        PODMAN_ARGS="${PODMAN_ARGS[@]}" "$REPO_ROOT"/ci/container/build-image.sh
        unset -f docker
    fi
fi

if findmnt /hoststorage >/dev/null; then
    eprintln "Purging non-relevant container images"
    sudo podman "${PODMAN_ARGS[@]}" image prune -a -f --filter "reference!=$IMAGE"
fi

WORKDIR="/ic"
USER=$(whoami)

PODMAN_RUN_ARGS=(
    -w "$WORKDIR"

    -u "ubuntu:ubuntu"
    -e HOSTUSER="$USER"
    -e HOSTHOSTNAME="$HOSTNAME"
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

CACHE_DIR="${CACHE_DIR:-${HOME}/.cache}"

ZIG_CACHE="${CACHE_DIR}/zig-cache"
mkdir -p "${ZIG_CACHE}"

ICT_TESTNETS_DIR="/tmp/ict_testnets"
mkdir -p "${ICT_TESTNETS_DIR}"

trap 'rm -rf "${SUBUID_FILE}" "${SUBGID_FILE}"' EXIT
SUBUID_FILE=$(mktemp --suffix=containerrun)
SUBGID_FILE=$(mktemp --suffix=containerrun)

IDMAP="uids=$(id -u)-1000-1;gids=$(id -g)-1000-1"

PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}",idmap="${IDMAP}"
    --mount type=bind,source="${CACHE_DIR:-${HOME}/.cache}",target="${CTR_HOME}/.cache",idmap="${IDMAP}"
    --mount type=bind,source="${ZIG_CACHE}",target="/tmp/zig-cache",idmap="${IDMAP}"
    --mount type=bind,source="${ICT_TESTNETS_DIR}",target="${ICT_TESTNETS_DIR}",idmap="${IDMAP}"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh",idmap="${IDMAP}"
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws",idmap="${IDMAP}"
)

if [ "$(id -u)" = "1000" ]; then
    if [ -e "${HOME}/.gitconfig" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.gitconfig",target="/home/ubuntu/.gitconfig",idmap="${IDMAP}"
        )
    fi

    if [ -e "${HOME}/.bash_history" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.bash_history",target="/home/ubuntu/.bash_history",idmap="${IDMAP}"
        )

    fi
    if [ -e "${HOME}/.local/share/fish" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.local/share/fish",target="/home/ubuntu/.local/share/fish",idmap="${IDMAP}"
        )
    fi
    if [ -e "${HOME}/.zsh_history" ]; then
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.zsh_history",target="/home/ubuntu/.zsh_history",idmap="${IDMAP}"
        )
    fi

    if findmnt /hoststorage >/dev/null; then
        # use host's storage for cargo target
        # * shared with VSCode's devcontainer, see .devcontainer/devcontainer.json
        # this configuration improves performance of rust-analyzer
        if [ ! -d /hoststorage/cache/cargo ]; then
            sudo mkdir -p /hoststorage/cache/cargo
            sudo chown -R 1000:1000 /hoststorage/cache/cargo
        fi
        PODMAN_RUN_ARGS+=(
            --mount type=bind,source="/hoststorage/cache/cargo",target="/ic/target"
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
    eprintln "No ssh-agent to forward."
fi

# Create dynamic subuid/subgid files for the user to run nested containers
echo "ubuntu:100000:65536" >$SUBUID_FILE
chmod +r ${SUBUID_FILE}
echo "ubuntu:100000:65536" >$SUBGID_FILE
chmod +r ${SUBGID_FILE}
PODMAN_RUN_ARGS+=(
    --mount type=bind,source="${SUBUID_FILE}",target="/etc/subuid"
    --mount type=bind,source="${SUBGID_FILE}",target="/etc/subgid"
)

# make sure we have all bind-mounts
mkdir -p ~/.{aws,ssh,cache,local/share/fish} && touch ~/.{zsh,bash}_history

PODMAN_RUN_USR_ARGS=()
if [ -f "$HOME/.container-run.conf" ]; then
    # conf file with user's custom PODMAN_RUN_USR_ARGS
    eprintln "Sourcing user's ~/.container-run.conf"
    source "$HOME/.container-run.conf"
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
other_args="--pids-limit=-1 -i $tty_arg --log-driver=none --rm --privileged --network=host --cgroupns=host"
# Privileged rootful podman is required due to requirements of IC-OS guest build;
# additionally, we need to use hosts's cgroups and network.
if [ $# -eq 0 ]; then
    set -x
    exec sudo podman "${PODMAN_ARGS[@]}" run $other_args "${PODMAN_RUN_ARGS[@]}" ${PODMAN_RUN_USR_ARGS[@]} -w "$WORKDIR" "$IMAGE" "${USHELL:-/usr/bin/bash}"
else
    set -x
    exec sudo podman "${PODMAN_ARGS[@]}" run $other_args "${PODMAN_RUN_ARGS[@]}" ${PODMAN_RUN_USR_ARGS[@]} -w "$WORKDIR" "$IMAGE" "$@"
fi
