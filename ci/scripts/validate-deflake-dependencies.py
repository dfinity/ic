#!/usr/bin/env python3
#
#   validate-deflake-dependencies.py BASE FIX
#
# Validates the dependency changes from the git revision BASE to FIX for ci/scripts/validate-deflake-bundle.sh, which
# rejects changes to the root Cargo.toml and to other lockfiles. Dependencies may only be added or removed as
# `name = { workspace = true }`, whose versions and features come from the root Cargo.toml: apart from those, each
# changed Cargo.toml must parse to the same as before, and Cargo.lock may only add or remove the packages they select in
# those crates' dependencies. Exits with a message at the first violation.

import re
import subprocess
import sys

import tomllib

base, fix = sys.argv[1:]
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


def inherited(manifest):
    return {
        name
        for table in tables(manifest)
        for kind in kinds
        for name, dep in table.get(kind, {}).items()
        if isinstance(dep, dict) and dep.get("workspace") is True
    }


# The workspace dependencies, which can rename their packages.
workspace = load(base, "Cargo.toml").get("workspace", {}).get("dependencies", {})


def package(name):
    dependency = workspace.get(name)
    return dependency.get("package", name) if isinstance(dependency, dict) else name


def put(table, key, value):
    # Empty tables are left out, so that one that only listed workspace dependencies is the same as none.
    if value:
        table[key] = value
    else:
        table.pop(key, None)


def without_workspace_dependencies(manifest):
    for table in tables(manifest):
        for kind in kinds:
            put(table, kind, {name: dep for name, dep in table.get(kind, {}).items() if dep != {"workspace": True}})
    put(manifest, "target", {target: table for target, table in manifest.get("target", {}).items() if table})
    return manifest


# The crates of the changed manifests, and the dependencies each crate adds, removes and inherits from the workspace.
crates, changes = {}, {}
diff = ["git", "diff", "--no-renames", "--name-only", "-z", base, fix, "--", "*Cargo.toml"]
for path in subprocess.check_output(diff, text=True).split("\0"):
    if path:
        old, new = load(base, path), load(fix, path)
        added, removed = names(new) - names(old), names(old) - names(new)
        if unknown := added - set(workspace):
            sys.exit(f"{path} adds dependencies the root Cargo.toml doesn't have: {', '.join(sorted(unknown))}")
        crates[path] = new.get("package", {}).get("name")
        changes[crates[path]] = (added, removed, inherited(new))
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
# The nested workspaces have lockfiles of their own, which the fix can't change, so only the manifests of the crates
# of the root workspace, which have no source in Cargo.lock, may change.
members = {name for name, _, source in old_packages if source is None}
if outside := [path for path, crate in crates.items() if crate not in members]:
    sys.exit(f"the fix changes manifests outside the root workspace: {', '.join(outside)}")

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
    if (
        not isinstance(dependency, dict)
        or dependency.keys() & {"git", "path", "registry"}
        or "version" not in dependency
    ):
        sys.exit(f"can't tell which {name} in Cargo.lock {key} selects")
    selected = [
        v for n, v, source in old_packages if n == name and source == CRATES_IO and matches(dependency["version"], v)
    ]
    if len(selected) != 1:
        sys.exit(f"can't tell which {name} in Cargo.lock {key} selects")
    version = selected[0]
    return f"{name} {version}" if versions.count(version) == 1 else f"{name} {version} ({CRATES_IO})"


for (name, version, source), old in old_packages.items():
    new = new_packages[(name, version, source)]
    old_list, new_list = old.pop("dependencies", []), new.pop("dependencies", [])
    if not all(isinstance(deps, list) and all(isinstance(d, str) for d in deps) for deps in (old_list, new_list)):
        sys.exit(f"Cargo.lock lists the dependencies of {name} {version} as something other than strings")
    if len(set(new_list)) != len(new_list):
        sys.exit(f"Cargo.lock lists a dependency of {name} {version} twice")
    old_deps, new_deps = set(old_list), set(new_list)
    # Only the crates of the workspace, which have no source, can have changed manifests.
    added, removed, inherits = changes.get(name, (set(), set(), set())) if source is None else (set(), set(), set())
    # Cargo.lock keeps a dependency while another workspace dependency still selects its package.
    kept = {reference(k) for k in inherits if package(k) in set(map(package, removed))}
    added, removed = set(map(reference, added)) - old_deps, (set(map(reference, removed)) - kept) & old_deps
    if old != new or new_deps - old_deps != added or old_deps - new_deps != removed:
        sys.exit(f"Cargo.lock doesn't match the dependency changes of {name} {version}")
