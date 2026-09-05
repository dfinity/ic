#!/usr/bin/env bash
#
# Integration test for ci/container/container-run.sh.
#
# Starts containers from this checkout and from a temporary linked git
# worktree next to it, and asserts the contract of container-run.sh:
#   - the checkout is mounted at its host path and is the working directory,
#     nothing is mounted at /ic and no BAZELRC is injected;
#   - git works in the main checkout and in a linked worktree, and gc's
#     automatic worktree pruning is disabled;
#   - bazel's default output base is md5(host path) under the shared
#     output_user_root, so it differs per checkout, and the main checkout's
#     bazel server survives a bazel run from another checkout;
#   - build-ic.sh drops into the ic-build container, whether invoked with a
#     repo-relative or an absolute host path.
#
# Usage (on the host, from any directory; not inside a container):
#   ./ci/container/test-container-run.sh                          # podman
#   CONTAINER_RUNTIME=docker ./ci/container/test-container-run.sh # docker
#
# Notes:
#   - A dirty working tree is fine; the temporary worktree checks out HEAD, so
#     its copies of get-image-tag.sh and build-ic.sh are HEAD's, while
#     container-run.sh under test is always this checkout's working copy.
#   - All containers use a throwaway cache directory (CACHE_DIR) under
#     ~/.cache, so the checkout's real bazel output base and any running bazel
#     server are never touched. Bazel is downloaded into it once per run.
#   - The temporary worktree is created next to the checkout (needs a writable
#     parent directory) and removed at exit, together with the throwaway cache.
#     A SIGKILL can leave a <checkout>-test-wt.XXXXXX directory behind.
#   - Deliberate local failures: a ~/.container-run.conf that mounts something
#     at /ic or sets BAZELRC, or a user.bazelrc with `startup --output_base`.
#   - On hosts where sudo prompts, run `sudo -v` first (podman needs it).

set -eEuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && git rev-parse --show-toplevel)"
RUN="$REPO_ROOT/ci/container/container-run.sh"
RUNTIME="${CONTAINER_RUNTIME:-podman}"

fails=0
ok() { echo "ok - $*"; }
nok() {
    echo "not ok - $*"
    fails=$((fails + 1))
}
# check_eq <what> <actual> <expected>
check_eq() {
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        nok "$1: expected '$3', got '$2'"
    fi
}
section() {
    echo
    echo "### $1 (${SECONDS}s elapsed)"
}
# run_in <dir> [container-run.sh args...]: stdin from /dev/null so that
# container-run.sh never adds -i -t and behaves the same locally and on CI.
run_in() {
    local dir=$1
    shift
    (cd "$dir" && "$RUN" "$@" </dev/null)
}

# Assertions evaluated inside a container. Shipped into the container with
# `declare -f` (see run_probe), so nothing has to be staged into the checkout.
# probe <expected_root> <expected_common_dir> <expected_head> <expected_ctr_uid> <expected_owner_uid> [<temp_worktree>]
probe() {
    local expected_root=$1 expected_common_dir=$2 expected_head=$3
    local expected_ctr_uid=$4 expected_owner_uid=$5 wt=${6:-}
    fails=0
    check_eq "working directory is the host path" "$PWD" "$expected_root"
    if [ -e /ic ]; then
        nok "nothing is mounted at /ic (a ~/.container-run.conf mount at /ic causes this)"
    else
        ok "nothing is mounted at /ic"
    fi
    if [ -f .bazelversion ]; then
        ok "checkout is mounted (.bazelversion present)"
    else
        nok "checkout is mounted (.bazelversion missing)"
    fi
    check_eq "checkout is owned by the host uid" "$(stat -c %u .)" "$expected_owner_uid"
    check_eq "container uid" "$(id -u)" "$expected_ctr_uid"
    check_eq "BAZELRC is not injected" "${BAZELRC:-unset}" unset
    check_eq "git toplevel is the host path" "$(git rev-parse --show-toplevel)" "$expected_root"
    check_eq "git common dir resolves" "$(realpath "$(git rev-parse --git-common-dir)")" "$expected_common_dir"
    check_eq "git HEAD" "$(git rev-parse HEAD)" "$expected_head"
    if git status --porcelain >/dev/null; then
        ok "git status works"
    else
        nok "git status works"
    fi
    check_eq "gc.worktreePruneExpire" "$(git config --get gc.worktreePruneExpire || true)" never
    if [ -n "$wt" ]; then
        # The temporary worktree's checkout is not mounted in this container, so
        # git must list it as prunable; that is why pruning is disabled above.
        if git worktree list --porcelain | awk -v wt="$wt" 'BEGIN { RS = "" } index($0, "worktree " wt "\n") == 1 && /\nprunable/ { found = 1 } END { exit !found }'; then
            ok "other worktree is listed as prunable"
        else
            nok "other worktree is listed as prunable"
        fi
    fi
    # A dirty tree yields "<sha>-dirty"; only the sha matters here.
    check_eq "workspace_status.sh --stamp sees git" "$(bazel/workspace_status.sh --stamp | awk '/^STABLE_VERSION /{ print substr($2, 1, 40) }')" "$expected_head"
    # `bazel version` starts a server (creating the output base) without parsing
    # build options, so no module resolution or fetching beyond the bazel
    # download itself.
    local ob
    ob="$HOME/.cache/bazel/_bazel_$(id -un)/$(printf %s "$PWD" | md5sum | cut -c1-32)"
    if timeout 600 bazel version >/dev/null 2>&1; then
        ok "bazel starts"
    else
        nok "bazel starts"
    fi
    if [ -f "$ob/server/server.pid.txt" ]; then
        ok "default output base is md5(host path): $ob"
    else
        nok "default output base is md5(host path): $ob was not created"
    fi
    bazel shutdown >/dev/null 2>&1 || true
    echo "output_base=$ob"
    echo "probe_fails=$fails"
}

declare -A OB=()
# run_probe <label> <dir> <expected_root> [<temp_worktree>]
run_probe() {
    local label=$1 dir=$2 root=$3 wt=${4:-} out rc=0
    out="$(run_in "$dir" bash -c "$(declare -f ok nok check_eq probe); probe \"\$@\"" probe \
        "$root" "$EXPECTED_COMMON_DIR" "$HEAD_SHA" "$EXPECTED_CTR_UID" "$HOST_UID" "$wt")" || rc=$?
    printf '%s\n' "$out" | grep -E '^(ok|not ok) ' | sed "s/^/[$label] /" || true
    if [ "$rc" -ne 0 ]; then
        nok "$label: container exited with status $rc"
    fi
    local probe_fails
    probe_fails="$(printf '%s\n' "$out" | sed -n 's/^probe_fails=//p')"
    fails=$((fails + ${probe_fails:-1}))
    OB[$label]="$(printf '%s\n' "$out" | sed -n 's/^output_base=//p')"
}

# check_build_ic <label> <dir> <command...>
check_build_ic() {
    local label=$1 dir=$2 out rc=0
    shift 2
    out="$(cd "$dir" && "$@" </dev/null 2>"$TMPCACHE/build-ic.stderr")" || rc=$?
    if [ "$rc" -ne 0 ]; then
        nok "$label: exit status $rc"
        tail -n 5 "$TMPCACHE/build-ic.stderr"
        return
    fi
    if grep -q 'dropping into container' <<<"$out" && grep -q '^Usage:' <<<"$out"; then
        ok "$label: dropped into the container and printed the usage"
    else
        nok "$label: unexpected output: $(head -c 300 <<<"$out")"
    fi
    if grep -q 'ghcr.io/dfinity/ic-build[:@]' "$TMPCACHE/build-ic.stderr"; then
        ok "$label: used the ic-build image"
    else
        nok "$label: the ic-build image does not appear in the run command"
    fi
}

WT=""
WT_GITDIR=""
TMPCACHE=""
cleanup() {
    local rc=$?
    set +e
    if [ -n "$WT" ]; then
        git -C "$REPO_ROOT" worktree remove --force "$WT" 2>/dev/null || {
            # Only this test's registration is removed; never `git worktree prune`,
            # which would also prune a developer's legitimately absent worktrees.
            chmod -R u+w "$WT" 2>/dev/null
            rm -rf "$WT" "$WT_GITDIR" 2>/dev/null || sudo rm -rf "$WT" "$WT_GITDIR"
        }
    fi
    if [ -n "$TMPCACHE" ]; then
        chmod -R u+w "$TMPCACHE" 2>/dev/null # bazel's install base is read-only
        rm -rf "$TMPCACHE" 2>/dev/null || sudo rm -rf "$TMPCACHE"
    fi
    exit "$rc"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

section "setup (CONTAINER_RUNTIME=$RUNTIME)"
id
ls -l /dev/kvm /dev/net/tun /dev/fuse 2>&1 || true
HOST_UID="$(id -u)"
case "$HOST_UID" in
    1000 | 1001) EXPECTED_CTR_UID="$HOST_UID" ;; # ubuntu, buildifier
    *) EXPECTED_CTR_UID=0 ;;                     # container-run.sh falls back to root
esac
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
# Also correct when this script itself runs from a linked worktree: the
# temporary worktree shares the same common dir.
EXPECTED_COMMON_DIR="$(realpath "$(git -C "$REPO_ROOT" rev-parse --git-common-dir)")"

mkdir -p "$HOME/.cache"
TMPCACHE="$(mktemp -d "$HOME/.cache/test-container-run.XXXXXX")"
export CACHE_DIR="$TMPCACHE" # read by container-run.sh like -c/--cache-dir
echo "checkout:   $REPO_ROOT"
echo "cache dir:  $TMPCACHE"

parent="$(dirname "$REPO_ROOT")"
if [ -w "$parent" ]; then
    WT="$(mktemp -d "$parent/$(basename "$REPO_ROOT")-test-wt.XXXXXX")"
    git -C "$REPO_ROOT" worktree add --detach "$WT" HEAD >/dev/null
    WT_GITDIR="$(git -C "$WT" rev-parse --absolute-git-dir)"
    echo "worktree:   $WT"
else
    echo "# SKIP: $parent is not writable; skipping the worktree and concurrency sections"
fi

section "main checkout"
run_probe main "$REPO_ROOT" "$REPO_ROOT" "$WT"
if [ -e "$TMPCACHE/container-run" ]; then
    nok "no rc file is written to the cache dir"
else
    ok "no rc file is written to the cache dir"
fi

if [ -n "$WT" ]; then
    section "linked worktree"
    run_probe worktree "$WT" "$WT"
    if [ -n "${OB[main]:-}" ] && [ -n "${OB[worktree]:-}" ] && [ "${OB[main]}" != "${OB[worktree]}" ]; then
        ok "output bases differ between checkouts"
    else
        nok "output bases differ between checkouts: '${OB[main]:-}' vs '${OB[worktree]:-}'"
    fi
    if git -C "$REPO_ROOT" worktree list --porcelain | grep -Fxq "worktree $WT"; then
        ok "worktree still registered on the host"
    else
        nok "worktree still registered on the host"
    fi

    section "concurrency: the main checkout's bazel server survives a bazel run from another checkout"
    # If the two checkouts shared an output base, the worktree container's
    # server would replace the main container's (their pids are invisible to
    # each other across PID namespaces) and the pid below would change.
    main_cmd='set -e
        ob="$HOME/.cache/bazel/_bazel_$(id -un)/$(printf %s "$PWD" | md5sum | cut -c1-32)"
        timeout 600 bazel version >/dev/null 2>&1
        p1=$(cat "$ob/server/server.pid.txt")
        touch "$HOME/.cache/.main-ready"
        for _ in $(seq 300); do [ -e "$HOME/.cache/.wt-done" ] && break; sleep 1; done
        [ -e "$HOME/.cache/.wt-done" ] || { echo "timed out waiting for the worktree container"; exit 2; }
        timeout 600 bazel version >/dev/null 2>&1
        p2=$(cat "$ob/server/server.pid.txt")
        echo "main checkout: bazel server pid before=$p1 after=$p2"
        bazel shutdown >/dev/null 2>&1 || true
        [ "$p1" = "$p2" ]'
    run_in "$REPO_ROOT" bash -c "$main_cmd" &
    main_job=$!
    for _ in $(seq 300); do
        [ -e "$TMPCACHE/.main-ready" ] && break
        sleep 1
    done
    if [ -e "$TMPCACHE/.main-ready" ]; then
        if run_in "$WT" bash -c 'timeout 600 bazel version >/dev/null 2>&1; bazel shutdown >/dev/null 2>&1 || true; touch "$HOME/.cache/.wt-done"'; then
            ok "worktree container ran bazel"
        else
            nok "worktree container ran bazel"
        fi
    else
        nok "main container became ready"
        touch "$TMPCACHE/.wt-done"
    fi
    if wait "$main_job"; then
        ok "main checkout's bazel server pid unchanged"
    else
        nok "main checkout's bazel server was replaced (or its container failed)"
    fi
fi

section "build-ic.sh drops into the ic-build container"
check_build_ic "repo-relative invocation" "$REPO_ROOT" ./ci/container/build-ic.sh --help
check_build_ic "absolute host path invocation" "$REPO_ROOT" "$REPO_ROOT/ci/container/build-ic.sh" --help

section "summary"
echo "failures: $fails"
exit $((fails > 0))
