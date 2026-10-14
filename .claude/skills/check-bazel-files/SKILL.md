---
name: check-bazel-files
description: Use after editing any Bazel file — BUILD.bazel, MODULE.bazel (including bazel/rust.MODULE.bazel), or a .bzl file — to validate the change without paying for a full build, and to auto-format it.
---

# Checking Bazel file changes

Two fast checks after editing `BUILD.bazel`, `MODULE.bazel`, or `.bzl` files,
run from the repository root (`cd "$(git rev-parse --show-toplevel)"`):

## 1. Validate with `--nobuild`

```sh
bazel build //... --nobuild
```

This loads and analyzes the entire workspace — catching `BUILD.bazel`/`.bzl`
syntax errors, bad `load()`s, broken labels, and analysis-phase failures across
every package — without actually building anything. It's much cheaper than a
real build and covers the whole repo rather than just the directly affected
targets, which matters because a bad `MODULE.bazel`/`.bzl` change (e.g. a
macro used repo-wide) can break packages far from the file you touched.

Fix any errors it reports.

## 2. Format with buildifier

```sh
bazel run //:buildifier
```

Auto-formats and lint-fixes every `BUILD.bazel`/`.bzl` file in place (see the
`buildifier` target in `bazel/BUILD.bazel`, aliased at `//:buildifier`). To
only check without writing changes (e.g. to see a diff first), use
`bazel run //:buildifier.check` instead.

## Notes

- If a change touched a crate dependency, keep the Cargo and Bazel builds in
  line: a third-party crate lives in **both** the root `Cargo.toml`
  (`[workspace.dependencies]`) and `bazel/rust.MODULE.bazel` (as a
  `crate.spec(...)`), so mirror the change across both (matching package,
  version, features), then repin per the **Repin** step in `.claude/CLAUDE.md`
  (`./bin/bazel-pin.sh`) — `--nobuild` alone won't catch a stale
  `@crate_index`.
- If `bazel` isn't available or reachable in your current environment, see the
  **run-in-dev-container** and **build-without-dfinity-infra** skills.
