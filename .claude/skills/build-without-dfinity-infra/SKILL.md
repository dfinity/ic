---
name: build-without-dfinity-infra
description: Use when you need to run a Bazel build or test outside DFINITY's internal infrastructure — i.e. without access to the internal remote cache / remote downloader (bazel-remote.idx.dfinity.network), e.g. on a personal machine, in a sandbox, or for a reproducibility check. Two ways: --config=local, or bypassing the workspace bazelrc.
---

# Building without DFINITY's internal infrastructure

The repo's `.bazelrc` imports `bazel/conf/.bazelrc.internal`, which points Bazel
at DFINITY's internal remote cache and remote downloader
(`bazel-remote.idx.dfinity.network`). These endpoints are reachable only from
inside DFINITY's internal network — in practice that essentially means a
**devenv** machine. They are **not** available on, e.g., a namespace.so devbox,
a sandbox, or CI without those credentials, where a plain `bazel build` will fail
or stall.

If you're unsure whether the infra is reachable from where you are, probe it:

```sh
curl -sS --max-time 5 -o /dev/null https://bazel-remote.idx.dfinity.network \
    && echo "internal cache reachable" \
    || echo "internal cache NOT reachable — build with --config=local"
```

When it's not reachable, build with one of the two approaches below.

## Option 1 — `--config=local` (recommended)

Keeps the full workspace configuration but empties `--remote_cache=` and
`--experimental_remote_downloader=` (see the `build:local` lines in
`bazel/conf/.bazelrc.internal`), so nothing contacts the internal endpoints:

```sh
bazel build --config=local //my:target
```

Use this when you want the normal build config minus the remote cache. It is also
what you want for reproducibility checks, where a cache hit could otherwise mask
non-determinism.

## Option 2 — bypass the workspace bazelrc entirely

Ignore the workspace `.bazelrc` (which is what pulls in `.bazelrc.internal`) and
load only the minimal build config, via *startup* options:

```sh
bazel --noworkspace_rc --bazelrc=bazel/conf/.bazelrc.build build //my:target
```

These are startup options (before the `build` subcommand), and `--bazelrc` is
resolved relative to the current working directory. Use this when you want
nothing from the workspace/internal config at all — only the settings required to
build.

## Which to use

Prefer `--config=local`: it's a single build flag and keeps the rest of the
workspace config intact. Reach for the `--noworkspace_rc` form only when you
specifically need to exclude everything the workspace `.bazelrc` imports.

## Running in the dev container

This is orthogonal to *where* you build — still run these through the pinned dev
container. See the **run-in-dev-container** skill for how to invoke
`container-run.sh`, including the podman/docker runtime choice for hosts without
podman.

## Caveat: system tests won't work

These flags only drop the remote cache/downloader; they can't replace the rest of
the internal infrastructure. In particular, **system tests will not run**: they
provision VMs via Farm, which lives inside DFINITY's internal network and is
unreachable from outside it. `--config=local` removes the cache but cannot
substitute Farm. Limit yourself to `bazel build` and non-system tests.
