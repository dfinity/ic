#!/usr/bin/env bash
set -eEuo pipefail

## Supports two container runtimes, selected via the CONTAINER_RUNTIME env var:
## 'podman' (default, rootful & privileged) and 'docker' (using docker daemon).

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

# Container runtime to use: 'podman' (default) or 'docker'.
RUNTIME="${CONTAINER_RUNTIME:-podman}"
if [ "$RUNTIME" != podman ] && [ "$RUNTIME" != docker ]; then
    eprintln "Unsupported CONTAINER_RUNTIME '$RUNTIME' (expected 'podman' or 'docker')."
    exit 1
fi
eprintln "Using container runtime '$RUNTIME'"

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

if [ "$RUNTIME" = docker ]; then
    CONTAINER_CMD=(docker)
elif [ "$DEVENV" = true ]; then
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

# Check for a locally-available image (podman has `image exists`; docker doesn't,
# so use `image inspect`) and pull or build it if it's missing.
if [ "$RUNTIME" = docker ]; then
    image_exists_cmd=("${CONTAINER_CMD[@]}" image inspect "$IMAGE")
else
    image_exists_cmd=("${CONTAINER_CMD[@]}" image exists "$IMAGE")
fi
if ! "${image_exists_cmd[@]}" >/dev/null 2>&1; then
    if ! "${CONTAINER_CMD[@]}" pull "$IMAGE"; then
        "$REPO_ROOT"/ci/container/build-image.sh --image "$IMAGE_NAME"
    fi
fi

# On the devenv we issue a warning if the images start taking up a lot of space.
# Podman does not have a dedicated layer cache like docker, so we avoid nuking dangling/unused images unless space becomes a concern;
# this allows new image builds to benefit from cached layers.
# We only issue a warning so that the user can GC when it's most convenient.
# This is podman-specific: docker manages its own layer cache and reports image
# sizes in a different JSON shape (a stream of objects without a RawSize field),
# so we skip the check under docker.
if [ "$DEVENV" = true ] && [ "$RUNTIME" = podman ]; then
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

# make sure we have all bind-mounts
# ~/.aws, ~/.ssh: credentials forwarded to the container
# ~/.cache: used as cache persisted across containers (cargo, etc)
# ~/.claude: persisted claude settings
mkdir -p ~/.{aws,ssh,cache,claude}

RUNTIME_RUN_ARGS=(
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

    --mount type=bind,source="${REPO_ROOT}",target="${WORKDIR}"       # mount the local repo checkout
    --mount type=bind,source="${ZIG_CACHE}",target="/tmp/zig-cache"   # C toolchain cache, persisted to speed up rebuilds
    --mount type=bind,source="${CACHE_DIR}",target="${CTR_CACHE_DIR}" # persisted root for caches (cargo, etc)

    # mount credentials & settings
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh"
    --mount type=bind,source="${HOME}/.claude",target="${CTR_HOME}/.claude"

    --mount type=tmpfs,target="/tmp/containers" # expected by ic-os build
)

# Privilege/isolation flags required by the IC-OS guest build, per runtime.
if [ "$RUNTIME" = docker ]; then
    # Under docker the IC-OS build runs (rootless) podman *inside* this
    # container. That nested podman needs: /dev/fuse for fuse-overlayfs storage;
    # unconfined seccomp/apparmor and disabled labeling for its syscalls; an
    # unmasked /proc (systempaths=unconfined) so it can mount its own procfs;
    # CAP_SYS_ADMIN so newuidmap can set up the nested user namespace; and host
    # networking so the inner build reaches the registry. This is much narrower
    # than the --privileged podman uses below.
    #
    # /dev/kvm and /dev/net/tun are additionally required by the local
    # system-test backend (the `_local` tests; see
    # rs/tests/driver/src/driver/local_backend.rs): it boots QEMU VMs (/dev/kvm)
    # and creates a per-group Linux bridge and per-VM TAP devices (`ip tuntap
    # add`, which opens /dev/net/tun). It does the latter inside a private
    # user+network namespace it unshares itself, gaining CAP_NET_ADMIN over that
    # namespace with no capability added to the container (the unprivileged
    # userns nesting is already permitted here) -- so no --cap-add NET_ADMIN.
    RUNTIME_RUN_ARGS+=(
        --device /dev/fuse
        --device /dev/kvm
        --device /dev/net/tun
        --security-opt seccomp=unconfined
        --security-opt apparmor=unconfined
        --security-opt label=disable
        --security-opt systempaths=unconfined
        --cap-add SYS_ADMIN
        --network=host
    )
else
    # Privileged rootful podman is required due to requirements of IC-OS guest build;
    # additionally, we need to use hosts's cgroups and network.
    RUNTIME_RUN_ARGS+=(--pids-limit=-1 --privileged --network=host --cgroupns=host)
fi

# In the devenv, inject some extra files into the container for convenience
if [ "$DEVENV" = true ]; then
    if [ -e "${HOME}/.gitconfig" ]; then
        RUNTIME_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.gitconfig",target="/home/ubuntu/.gitconfig"
        )
    fi

    if [ -e "${HOME}/.bash_history" ]; then
        RUNTIME_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.bash_history",target="/home/ubuntu/.bash_history"
        )

    fi
    if [ -e "${HOME}/.local/share/fish" ]; then
        RUNTIME_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.local/share/fish",target="/home/ubuntu/.local/share/fish"
        )
    fi
    if [ -e "${HOME}/.zsh_history" ]; then
        RUNTIME_RUN_ARGS+=(
            --mount type=bind,source="${HOME}/.zsh_history",target="/home/ubuntu/.zsh_history"
        )
    fi

    # persist cargo target across containers
    # * shared with VSCode's devcontainer, see .devcontainer/devcontainer.json
    # this configuration improves performance of rust-analyzer
    RUNTIME_RUN_ARGS+=(
        -e CARGO_TARGET_DIR="$CTR_CACHE_DIR/cargo"
    )
fi

if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -e "${SSH_AUTH_SOCK:-}" ]; then
    RUNTIME_RUN_ARGS+=(
        -v "$SSH_AUTH_SOCK:/ssh-agent"
        -e SSH_AUTH_SOCK="/ssh-agent"
    )
else
    eprintln "No ssh-agent to forward."
fi

# if a user is attached, make it interactive and create tty
if tty >/dev/null 2>&1; then
    RUNTIME_RUN_ARGS+=(-i -t)
fi

if [ -f "$HOME/.container-run.conf" ]; then
    # conf file with user's custom PODMAN_RUN_USR_ARGS
    # This file is very handy but is a source of non-hermeticity, and issues
    # related to it are hard to track down so we print a bold yellow message
    # when it is in use.
    warn "Sourcing user's ~/.container-run.conf"
    source "$HOME/.container-run.conf"
    RUNTIME_RUN_ARGS+=("${PODMAN_RUN_USR_ARGS[@]}")
fi

set -x
exec "${CONTAINER_CMD[@]}" run "${RUNTIME_RUN_ARGS[@]}" "$IMAGE" "${cmd[@]}"
