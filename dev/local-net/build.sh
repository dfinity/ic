#!/usr/bin/env bash
#
# Build x86_64 Linux IC binaries via the official ic-build container
# (running under Rosetta on Apple Silicon), then package them into a
# slim runtime image (ic-replica:dev).
#
# Outputs:
#   ./out/        host-visible binaries (for inspection / debugging)
#   ./cache/      persistent bazel disk cache (DO NOT delete between builds)
#   ic-replica:dev   tagged Docker image
#
# Environment:
#   IC_REPO        path to the IC repo (default: $HOME/code/dfinity)
#   TARGETS        space-separated bazel target labels to build
#                  (default: all binaries needed for a local 4-node network)
#   SKIP_IMAGE=1   only build binaries, skip the runtime image step
#   SKIP_BAZEL=1   only build the runtime image from existing ./out/
set -euo pipefail

LOCAL_NET_DIR="$(cd "$(dirname "$0")" && pwd)"
# When this script lives at <repo>/dev/local-net/build.sh, two dirs up is
# the IC repo root. Override with IC_REPO=... if the script is elsewhere.
IC_REPO="${IC_REPO:-$(cd "$LOCAL_NET_DIR/../.." && pwd)}"

if [ ! -f "$IC_REPO/rs/replica/BUILD.bazel" ]; then
    echo "ERROR: \$IC_REPO=$IC_REPO does not look like the IC repo." >&2
    echo "       Set IC_REPO to the absolute path of dfinity/ic." >&2
    exit 1
fi

BUILDER_TAG="$(cat "$IC_REPO/ci/container/TAG")"
BUILDER_IMG="ghcr.io/dfinity/ic-build:${BUILDER_TAG}"

DEFAULT_TARGETS=(
    "//rs/replica:replica"
    "//rs/canister_sandbox:canister_sandbox"
    "//rs/canister_sandbox:compiler_sandbox"
    "//rs/canister_sandbox:sandbox_launcher"
    "//rs/prep:ic-prep"
    "//rs/registry/admin:ic-admin"
    "//rs/nns/init:ic-nns-init"
)
read -r -a TARGETS <<<"${TARGETS:-${DEFAULT_TARGETS[*]}}"

CACHE_DIR="$LOCAL_NET_DIR/cache"
OUT_DIR="$LOCAL_NET_DIR/out"
mkdir -p "$CACHE_DIR" "$OUT_DIR"

if [ "${SKIP_BAZEL:-0}" != "1" ]; then
    echo "==> Bazel build (x86_64 Linux via Rosetta)"
    echo "    Builder:  $BUILDER_IMG"
    echo "    IC repo:  $IC_REPO"
    echo "    Cache:    $CACHE_DIR"
    echo "    Out:      $OUT_DIR"
    echo "    Targets:  ${TARGETS[*]}"
    echo

    docker run --rm \
        --platform=linux/amd64 \
        -v "$IC_REPO:/ic" \
        -v "$CACHE_DIR:/cache" \
        -v "$OUT_DIR:/out" \
        -w /ic \
        "$BUILDER_IMG" \
        bash -eu -o pipefail -c "
            bazel build \
                --disk_cache=/cache/bazel-disk \
                --repository_cache=/cache/bazel-repo \
                ${TARGETS[*]}

            # Copy out binaries by basename (last path component of the label).
            for label in ${TARGETS[*]}; do
                pkg=\${label#//}; pkg=\${pkg%%:*}
                name=\${label##*:}
                src=bazel-bin/\$pkg/\$name
                # Some labels output dashed names with underscore source paths
                if [ ! -f \"\$src\" ]; then
                    alt=\$(echo \"\$src\" | tr '-' '_')
                    [ -f \"\$alt\" ] && src=\"\$alt\"
                fi
                # Use the canonical binary name in /out
                out_name=\$name
                # Rename the replica binary to ic-replica so users don't confuse
                # it with the bazel rule name.
                [ \"\$name\" = replica ] && out_name=ic-replica
                cp -L \"\$src\" \"/out/\$out_name\"
            done

            chmod 0755 /out/*
            ls -lh /out/
        "
fi

if [ "${SKIP_IMAGE:-0}" != "1" ]; then
    echo
    echo "==> Building runtime image ic-replica:dev"
    docker buildx build \
        --platform=linux/amd64 \
        --load \
        -t ic-replica:dev \
        -f "$LOCAL_NET_DIR/Dockerfile.runtime" \
        "$LOCAL_NET_DIR"

    echo
    echo "Done. Sanity-check the binaries can at least exec:"
    # ic-replica's --version prints the version but then its config loader
    # tries to consume the flag and complains; head -1 drops the noise.
    docker run --rm --platform=linux/amd64 ic-replica:dev /usr/local/bin/ic-replica --version 2>&1 | head -1 || true
    docker run --rm --platform=linux/amd64 ic-replica:dev /usr/local/bin/ic-prep --help 2>&1 | head -1 || true
fi
