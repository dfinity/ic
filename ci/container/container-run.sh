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

die() {
    warn "$@"
    exit 1
}

case "$IMAGE_NAME" in
    ic-dev | ic-build) ;;
    *) die "Unknown image '$IMAGE_NAME' (expected ic-dev or ic-build)" ;;
esac

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE_REPO="ghcr.io/dfinity/$IMAGE_NAME"
IMAGE_TAG="$("$REPO_ROOT"/ci/container/get-image-tag.sh)"
PINNED_TAG="$(<"$REPO_ROOT/ci/container/TAG")"
DIGEST_FILE="$REPO_ROOT/ci/container/$IMAGE_NAME.digest"
# By default the script refuses to run any image that is not verified against
# the committed digest pin. CONTAINER_RUN_ALLOW_UNPINNED=1 opts out for this run:
# build the image locally from the checkout when no reviewed pin exists for the
# working tree, or reuse an existing local image when the pinned pull fails.
# Only the exact value 1 opts out, so that 0, false or a typo cannot silently
# disable the check.
case "${CONTAINER_RUN_ALLOW_UNPINNED:-}" in
    "") ALLOW_UNPINNED="" ;;
    1) ALLOW_UNPINNED=1 ;;
    *) die "CONTAINER_RUN_ALLOW_UNPINNED must be unset or exactly '1' (got '${CONTAINER_RUN_ALLOW_UNPINNED}')" ;;
esac
# Set when the image about to run is NOT verified against a reviewed digest pin
# (built locally, or an existing local image reused because the pull failed).
LOCAL_IMAGE=false

image_exists() {
    if [ "$RUNTIME" = docker ]; then
        "${CONTAINER_CMD[@]}" image inspect "$1" >/dev/null 2>&1
    else
        "${CONTAINER_CMD[@]}" image exists "$1"
    fi
}

build_locally() {
    if [ -z "$ALLOW_UNPINNED" ]; then
        die "$1; refusing to build an unpinned image locally (set CONTAINER_RUN_ALLOW_UNPINNED=1 to run an image that is not verified against the committed digest)"
    fi
    warn "$1; building $IMAGE_REPO:$IMAGE_TAG locally from the checkout (this takes a while)"
    "$REPO_ROOT"/ci/container/build-image.sh --image "$IMAGE_NAME" --container-cmd "${CONTAINER_CMD[*]}"
    IMAGE="$IMAGE_REPO:$IMAGE_TAG"
    LOCAL_IMAGE=true
}

if [ "$IMAGE_TAG" = "$PINNED_TAG" ]; then
    [ -f "$DIGEST_FILE" ] || die "$DIGEST_FILE is missing: refusing to pull an unpinned image"
    IMAGE_DIGEST="$(<"$DIGEST_FILE")"
    if ! [[ $IMAGE_DIGEST =~ ^sha256:[0-9a-f]{64}$ ]]; then
        die "$DIGEST_FILE is malformed ('$IMAGE_DIGEST'): refusing to pull an unpinned image"
    fi
    IMAGE="$IMAGE_REPO@$IMAGE_DIGEST"
    if ! image_exists "$IMAGE" && image_exists "$IMAGE_REPO:$IMAGE_TAG"; then
        eprintln "Local image $IMAGE_REPO:$IMAGE_TAG is not verified against the pin (e.g. built locally); pulling the pinned image $IMAGE instead (one-time download)."
    fi
    if image_exists "$IMAGE" || "${CONTAINER_CMD[@]}" pull "$IMAGE"; then
        "${CONTAINER_CMD[@]}" tag "$IMAGE" "$IMAGE_REPO:$IMAGE_TAG" \
            || die "Failed to tag the verified image $IMAGE as $IMAGE_REPO:$IMAGE_TAG"
    elif [ -n "$ALLOW_UNPINNED" ] && image_exists "$IMAGE_REPO:$IMAGE_TAG"; then
        warn "Pinned image $IMAGE could not be pulled (offline?); reusing the existing local image $IMAGE_REPO:$IMAGE_TAG, which is NOT verified against the pin (CONTAINER_RUN_ALLOW_UNPINNED is set)."
        IMAGE="$IMAGE_REPO:$IMAGE_TAG"
        LOCAL_IMAGE=true
    else
        build_locally "Pinned image $IMAGE could not be pulled"
    fi
else
    warn "ci/container/{Dockerfile,init.sh,files/*} differ from what ci/container/TAG was built from:"
    warn "  computed tag: $IMAGE_TAG"
    warn "  pinned tag:   $PINNED_TAG"
    warn "No reviewed digest pin exists for the computed tag, and registry tags are mutable and unverified, so it is never pulled."
    warn "If you pushed this change, wait for the 'Container IC Build Image' workflow to commit TAG and *.digest to your branch, then 'git pull' and re-run."
    if [ -z "$ALLOW_UNPINNED" ]; then
        die "No reviewed digest pin exists for tag $IMAGE_TAG; refusing to run an unpinned image (set CONTAINER_RUN_ALLOW_UNPINNED=1 to build it locally from the checkout, or to reuse an existing local $IMAGE_REPO:$IMAGE_TAG)"
    fi
    IMAGE="$IMAGE_REPO:$IMAGE_TAG"
    image_exists "$IMAGE" || build_locally "No reviewed digest pin exists for tag $IMAGE_TAG"
    LOCAL_IMAGE=true
fi

if [ "$LOCAL_IMAGE" = true ]; then
    warn "Using image $IMAGE (NOT verified against a reviewed digest pin; CONTAINER_RUN_ALLOW_UNPINNED is set)"
else
    eprintln "Using image $IMAGE (verified against ci/container/$IMAGE_NAME.digest)"
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
    --mount type=bind,source="${CACHE_DIR}",target="${CTR_CACHE_DIR}" # persisted root for caches (cargo, etc)

    # mount credentials & settings
    --mount type=bind,source="${HOME}/.aws",target="${CTR_HOME}/.aws"
    --mount type=bind,source="${HOME}/.ssh",target="${CTR_HOME}/.ssh"
    --mount type=bind,source="${HOME}/.claude",target="${CTR_HOME}/.claude"

    --mount type=tmpfs,target="/tmp/containers" # expected by ic-os build
)

# Give every checkout its own bazel output base.
#
# Bazel derives the default output base from the md5 of the workspace path.
# Every checkout is mounted at the same path ($WORKDIR) with the same cache
# dir, so containers started from different checkouts (git worktrees or
# clones) would all use one output base. Each container also has its own PID
# namespace, so bazel's client cannot recognize the other container's server
# (it verifies the server pid via /proc), starts a second server in the same
# output base, and the first server then kills itself: its client fails with
# "Server terminated abruptly (error code: 14 ...)". Keying the output base on
# the host path of the checkout avoids this while keeping the install base,
# the repository cache and the repo contents cache (all of which live in the
# shared output_user_root) shared between checkouts.
#
# Bazel reads the rc files named in $BAZELRC in addition to the workspace
# .bazelrc (including its user.bazelrc import) and ~/.bazelrc, so the rest of
# the repository's bazel configuration still applies. The variable only
# exists inside the container, so host-side bazel invocations are unaffected.
# Keep only characters that are safe in the rc line, in $BAZELRC (comma-separated) and in
# a filename; the path hash below keeps the key unique.
REPO_NAME="$(printf '%s' "$(basename "$REPO_ROOT")" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)"
OUTPUT_BASE_KEY="$REPO_NAME-$(printf '%s' "$REPO_ROOT" | sha256sum | cut -c1-8)"
OUTPUT_BASE="$CTR_CACHE_DIR/bazel/_bazel_$CTR_USER/$OUTPUT_BASE_KEY"
BAZELRC_REL="container-run/$OUTPUT_BASE_KEY.bazelrc" # relative to the cache dir
mkdir -p "$(dirname "$CACHE_DIR/$BAZELRC_REL")"
echo "startup --output_base=$OUTPUT_BASE" >"$CACHE_DIR/$BAZELRC_REL"
RUNTIME_RUN_ARGS+=(-e BAZELRC="$CTR_CACHE_DIR/$BAZELRC_REL")
eprintln "Using bazel output base '$OUTPUT_BASE'"

# Support linked git worktrees (`git worktree add`).
#
# A linked worktree's .git is a file pointing into the main repository's .git
# directory on the host, which is not otherwise visible in the container, so
# git (and everything that uses it: --config=stamped, rust-lint.sh, ic-admin's
# build script under cargo, ...) would fail with "not a git repository".
# Bind-mount the common git dir at its host path so that the pointer resolves.
#
# Inside such a container `git worktree list` reports the linked worktrees as
# "prunable" because their host checkout paths are not visible, so never run
# `git worktree prune|repair|move|remove` in the container. For the same
# reason gc's automatic worktree pruning is disabled via GIT_CONFIG_*.
GIT_COMMON_DIR="$(cd "$REPO_ROOT" && realpath "$(git rev-parse --git-common-dir)")"
if [ "$GIT_COMMON_DIR" != "$REPO_ROOT/.git" ]; then
    eprintln "Detected linked git worktree; mounting '$GIT_COMMON_DIR'"
    RUNTIME_RUN_ARGS+=(
        --mount type=bind,source="$GIT_COMMON_DIR",target="$GIT_COMMON_DIR"
        -e GIT_CONFIG_COUNT=1
        -e GIT_CONFIG_KEY_0=gc.worktreePruneExpire
        -e GIT_CONFIG_VALUE_0=never
    )
fi

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
exec "${CONTAINER_CMD[@]}" run "${RUNTIME_RUN_ARGS[@]}" --pull=never "$IMAGE" "${cmd[@]}"
