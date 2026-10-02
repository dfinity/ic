#!/usr/bin/env bash
# Validates the fix that .github/workflows/fix-flaky-test.yml bundled in $RUNNER_TEMP/deflake and
# prepares its PR for ci/scripts/open-deflake-pr.sh: the fix is squashed into one commit on top of
# $BASE_SHA and only its tree and PR body come from the bundle. The branch, title and labels are
# derived from the trusted $SLUG, $LABEL and $LABELS. Exports BRANCH, NEW, TITLE and BODY_FILE to
# $GITHUB_ENV.

set -euo pipefail

die() {
    echo "needs_human: $*" >&2
    exit 1
}

bundle="$RUNNER_TEMP/deflake/deflake.bundle"
git fetch --quiet --depth=1 origin "$BASE_SHA"

# The header of the bundle lists its prerequisites (lines starting with '-') and its refs.
header="$(sed '/^$/q' "$bundle")"
[ "$(grep '^-' <<<"$header" | cut -c2-41)" == "$BASE_SHA" ] || die "the bundle doesn't build on $BASE_SHA"
[ "$(git bundle list-heads "$bundle" | cut -d' ' -f2-)" == refs/heads/deflake ] || die "the bundle has other refs than refs/heads/deflake"

fix=refs/deflake/fix
git -c transfer.fsckObjects=true fetch --quiet "$bundle" "+refs/heads/deflake:$fix" || die "the bundle can't be fetched"
git merge-base --is-ancestor "$BASE_SHA" "$fix" || die "the fix isn't on top of $BASE_SHA"
[ "$(git rev-list --count "$BASE_SHA..$fix")" -le 10 ] || die "the fix has more than 10 commits"
! git diff --quiet "$BASE_SHA" "$fix" || die "the fix doesn't change anything"

# The diffs are captured before checking them so that a failing git diff aborts the script, and a grep
# exiting early can't SIGPIPE git into a pipeline failure that reads as "no match".
git diff --no-renames --name-only -z "$BASE_SHA" "$fix" >"$RUNNER_TEMP/deflake-paths"
disallowed=()
while IFS= read -r -d '' path; do
    case "$path" in
        *.bzl | MODULE.bazel | *.MODULE.bazel | *.bazelrc | .gitattributes | */.gitattributes | .gitmodules | */Cargo.lock | rs/ic_os/config/types/*)
            disallowed+=("$path")
            ;;
        rs/* | packages/* | Cargo.lock) ;;
        *) disallowed+=("$path") ;;
    esac
done <"$RUNNER_TEMP/deflake-paths"
[ ${#disallowed[@]} -eq 0 ] || die "the fix changes disallowed files: ${disallowed[*]}"
raw="$(git diff --no-renames --raw "$BASE_SHA" "$fix")"
if awk '$1 ~ /^:(120000|160000)$/ || $2 == "120000" || $2 == "160000" {bad = 1} END {exit !bad}' <<<"$raw"; then
    die "the fix changes a symlink or submodule"
fi
# Dependencies may only be added or removed as `name = { workspace = true }`, whose versions and features come
# from the root Cargo.toml, which the fix can't change: apart from those, each changed Cargo.toml must parse to
# the same as before, and Cargo.lock may only add or remove the packages they select in those crates' dependencies.
git diff --no-renames --name-only -z "$BASE_SHA" "$fix" -- '*Cargo.toml' >"$RUNNER_TEMP/deflake-manifests"
python3 - "$BASE_SHA" "$fix" "$RUNNER_TEMP/deflake-manifests" <<'EOF' || die "the fix changes dependencies beyond adding or removing workspace dependencies"
import re
import subprocess
import sys
import tomllib

base, fix, manifests = sys.argv[1:]
kinds = ["dependencies", "dev-dependencies", "build-dependencies"]


def load(rev, path):
    show = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    if show.returncode != 0:
        sys.exit(f"{path} is added or deleted")
    return tomllib.loads(show.stdout)


def tables(manifest):
    return [manifest, *manifest.get("target", {}).values()]


def names(manifest):
    return {name for table in tables(manifest) for kind in kinds for name in table.get(kind, {})}


# The workspace dependencies, which can rename their packages.
workspace = load(base, "Cargo.toml").get("workspace", {}).get("dependencies", {})


def package(name):
    dependency = workspace.get(name)
    return dependency.get("package", name) if isinstance(dependency, dict) else name


def without_workspace_dependencies(manifest):
    for table in tables(manifest):
        for kind in kinds:
            dependencies = {name: dep for name, dep in table.get(kind, {}).items() if dep != {"workspace": True}}
            if dependencies:
                table[kind] = dependencies
            else:
                table.pop(kind, None)
    return manifest


# The dependencies each crate adds and removes.
changes = {}
for path in open(manifests).read().split("\0"):
    if path:
        old, new = load(base, path), load(fix, path)
        added, removed = names(new) - names(old), names(old) - names(new)
        if unknown := added - set(workspace):
            sys.exit(f"{path} adds dependencies the root Cargo.toml doesn't have: {', '.join(sorted(unknown))}")
        changes[new.get("package", {}).get("name")] = (added, removed)
        if without_workspace_dependencies(old) != without_workspace_dependencies(new):
            sys.exit(f"{path} changes beyond adding or removing workspace dependencies")


def lockfile(rev):
    lock = load(rev, "Cargo.lock")
    entries = lock.pop("package", [])
    keys = [(p.get("name"), p.get("version"), p.get("source")) for p in entries]
    if len(set(keys)) != len(keys):
        sys.exit("Cargo.lock has duplicate packages")
    return lock, dict(zip(keys, entries))


(old_metadata, old_packages), (new_metadata, new_packages) = lockfile(base), lockfile(fix)
if old_metadata != new_metadata or old_packages.keys() != new_packages.keys():
    sys.exit("Cargo.lock adds or removes packages or changes its metadata")

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def matches(requirement, version):
    # A bare version and ^ keep the leftmost non-zero component, ~ the minor version and = all given components.
    req = re.fullmatch(r"([~=^]?)([0-9]+(?:\.[0-9]+){0,2})", requirement.replace(" ", ""))
    ver = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", version)
    if not req or not ver:
        sys.exit(f"can't tell whether {version} satisfies {requirement}")
    parts, actual = [int(p) for p in req[2].split(".")], tuple(int(p) for p in ver.groups())
    leftmost = next((i + 1 for i, p in enumerate(parts) if p), len(parts))
    same = {"=": len(parts), "~": min(len(parts), 2)}.get(req[1], leftmost)
    return actual >= tuple(parts + [0] * (3 - len(parts))) and actual[:same] == tuple(parts[:same])


def reference(key):
    # How Cargo.lock refers to the package that a workspace dependency selects: by its name if that's unique,
    # else also by its version, and also by its source if that's still ambiguous.
    name, dependency = package(key), workspace.get(key)
    versions = [version for n, version, _ in old_packages if n == name]
    if len(versions) == 1:
        return name
    if isinstance(dependency, str):
        dependency = {"version": dependency}
    if not isinstance(dependency, dict) or dependency.keys() & {"git", "path", "registry"} or "version" not in dependency:
        sys.exit(f"can't tell which {name} in Cargo.lock {key} selects")
    selected = [v for n, v, source in old_packages if n == name and source == CRATES_IO and matches(dependency["version"], v)]
    if len(selected) != 1:
        sys.exit(f"can't tell which {name} in Cargo.lock {key} selects")
    version = selected[0]
    return f"{name} {version}" if versions.count(version) == 1 else f"{name} {version} ({CRATES_IO})"


for (name, version, source), old in old_packages.items():
    new = new_packages[(name, version, source)]
    old_deps, new_deps = set(old.pop("dependencies", [])), set(new.pop("dependencies", []))
    # Only the crates of the workspace, which have no source, can have changed manifests.
    added, removed = changes.get(name, (set(), set())) if source is None else (set(), set())
    added, removed = set(map(reference, added)), set(map(reference, removed))
    if old != new or not new_deps - old_deps <= added or not old_deps - new_deps <= removed:
        sys.exit(f"Cargo.lock changes {name} {version} beyond adding or removing its workspace dependencies")
EOF
numstat="$(git diff --no-renames --numstat "$BASE_SHA" "$fix")"
if grep -q $'^-\t-\t' <<<"$numstat"; then
    die "the fix changes binary files"
fi
changed="$(awk '{n += $1 + $2} END {print n + 0}' <<<"$numstat")"
[ "$changed" -le 1000 ] || die "the fix changes $changed lines"

author='claude[bot]'
email='209825114+claude[bot]@users.noreply.github.com'
title="fix: deflake $LABEL"
new="$(GIT_AUTHOR_NAME="$author" GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_NAME="$author" GIT_COMMITTER_EMAIL="$email" \
    git commit-tree "$fix^{tree}" -p "$BASE_SHA" -m "$title")"

body_file="$RUNNER_TEMP/pr-body.md"
{
    echo "This PR was created by $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$RUN_ID following \`.claude/skills/fix-flaky-tests/SKILL.md\` to deflake:"
    for label in $LABELS; do
        echo "* \`$label\`"
    done
    echo
    # Drop what could hide text from reviewers: HTML comments (also unterminated ones), link reference
    # definitions (which also serve as comments) and invisible, private-use or unassigned characters.
    head -c 60000 "$RUNNER_TEMP/deflake/body.md" \
        | perl -0777 -CSD -pe '1 while s/<!--.*?(?:-->|\z)//s; s/^ {0,3}\[[^\]\n]*\]:.*\n?//mg; s/[\p{Cf}\p{Co}\p{Cn}\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]//g'
} >"$body_file"

{
    echo "BRANCH=ai/deflake-$SLUG-$(date -u +%F)"
    echo "NEW=$new"
    echo "TITLE=$title"
    echo "BODY_FILE=$body_file"
} >>"$GITHUB_ENV"
