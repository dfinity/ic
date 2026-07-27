---
name: run-in-dev-container
description: Use when you need to run a command (build, test, tool) inside the IC dev container via ./ci/container/container-run.sh — including on a host that has Docker but not podman (set CONTAINER_RUNTIME=docker) — or when you need to keep a namespace.so devbox awake during long-running work.
---

# Running commands in the IC dev container

`./ci/container/container-run.sh` runs a command inside the pinned IC dev
container (the `ghcr.io/dfinity/ic-dev` image), bind-mounting the repo checkout
at `/ic` and reusing `~/.cache` for the Bazel/cargo/zig caches.

Prefer running builds and build tooling through it: it gives you the exact,
pinned toolchain environment, and standardizing on the container — regardless of
whether it's backed by podman or docker — keeps things simple and consistent.

## Choosing the container runtime

The script supports two runtimes, selected by the `CONTAINER_RUNTIME` env var:

- **podman** (default) — rootful and privileged.
- **docker** — for hosts that have the Docker daemon but **no podman**.

Which one to use depends on where you are:

- **namespace.so devboxes** (e.g. this machine — `test -d /.namespace`): use
  **docker**. podman isn't available there, and the namespace.so daemon can't do
  some things podman's setup expects (e.g. bind-mounting the host's `/tmp`).
- **DFINITY infra, in particular a "devenv" machine** (which `container-run.sh`
  detects via `/var/lib/cloud/instance` plus a `/hoststorage` mount): use
  **podman** — the default, so no env var needed.

On a docker host, prefix every invocation with `CONTAINER_RUNTIME=docker`:

```sh
# interactive shell in the container
CONTAINER_RUNTIME=docker ./ci/container/container-run.sh

# run a single command and exit
CONTAINER_RUNTIME=docker ./ci/container/container-run.sh <command> [args...]
```

If `CONTAINER_RUNTIME` is unsupported the script errors out early; if the chosen
runtime's daemon isn't reachable it prints which command it tried.

## Notes

- The repo is mounted at `/ic` and that's the working directory, so invoke
  repo-local scripts with a relative path, e.g.
  `CONTAINER_RUNTIME=docker ./ci/container/container-run.sh ./path/to/script.sh`.
- The image is pulled from `ghcr.io` on first use (large, one-time).
- Anything the command writes under `/ic` (or `~/.cache`) persists on the host,
  since those are bind-mounted.
- Don't nest: the script refuses to run inside an existing container.

## Keeping a namespace.so devbox awake for long-running work

On a namespace.so devbox (`test -d /.namespace`), the machine can go to sleep
during a long unattended operation — a multi-minute `bazel build`/`bazel
test`, a container image build/pull, etc. — killing it partway through.

Before starting long-running work, create the marker file:

```sh
mkdir -p /.namespace/tasks && touch /.namespace/tasks/stay-live
```

and remove it once the work is done, so the devbox is allowed to sleep again:

```sh
rm -f /.namespace/tasks/stay-live
```

This is independent of whether the work itself runs inside the dev container
or directly on the host.
