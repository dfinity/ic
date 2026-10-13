# Container Dev & Build Environment

Codebase for containerized build and development environment.
<br>
See [Dockerfile](Dockerfile) for info about required dependencies.

## Requirements

- x86-64 based system (at least 8 CPUs, 16 GB MEM/SWAP, 100 GB available disk space)
- Ubuntu 22.04 or newer
- [Podman](https://podman.io/getting-started/installation)

**Note:** With *Ubuntu 20.10* and newer, you can simply do `sudo apt install -y podman`. With older versions see Ubuntu section of [Podman Installation Guide](https://podman.io/getting-started/installation). It's recommended to use Ubuntu 22.04.

### Cloud Config

See [Ubuntu 22.04 Cloud Config](userdata-ubuntu-2204.yaml) for [Cloud-init](https://cloudinit.readthedocs.io/en/latest/).
You can simply replace `$SSH_KEY` and `$REVISION` variables in the file with values and feed it to *Ubuntu 22.04* cloud instance you're creating to build or verify IC artifacts. See the example snippet which gives you the final `userdata.yaml` that you can use.

```bash
export REVISION="ff8d2c62c88a84b744bb1114c17aa1ea3......e"
export SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPUaR2BDvN0ZDfQ+WFNa3NW3X3V3Qrxb7f6wn6ZbQkJm"
envsubst < userdata-ubuntu-2204.yaml > userdata.yaml
```

**Note:** Above `userdata.yaml` is possible for `$REVISION` that is newer then `08244b2bc9bbb19d417d37f6912acfebbdbf4f49` when `build-ic.sh` became available.

Cloud Config is being daily tested on official [Ubuntu 22.04 Image](https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64-disk-kvm.img).

## Building IC-OS

```bash
$ ./ci/container/build-ic.sh -i
$ # artifacts are available under ./artifacts directory
$ tree artifacts/
```

*Note:* This implies building binaries and canisters as IC-OS requires them.

## Building Binaries or Canisters

Only binaries:

```bash
$ ./ci/container/build-ic.sh -b
$ # artifacts are available under ./artifacts/binaries directory
$ ls -l artifacts/binaries
```

Only canisters:

```bash
$ ./ci/container/build-ic.sh -c
$ # artifacts are available under ./artifacts/canisters directory
$ ls -l artifacts/canisters
```

Both binaries and canisters:

```bash
$ ./ci/container/build-ic.sh -b -c
```

## Using `container-run.sh`

Using script `container-run.sh` is required and supported way for building and testing bazel targets!

### What you need to know

`container-run.sh` starts a fresh, throw-away (`--rm`) container from the pinned `ghcr.io/dfinity/ic-dev` image (or `ic-build` with `--image ic-build`) and runs the given command in it, or an interactive shell if no command is given. It supports two container runtimes, selected with `CONTAINER_RUNTIME=podman` (the default; rootful and `--privileged`) or `CONTAINER_RUNTIME=docker`. The exact `podman run`/`docker run` command is printed (`set -x`) right before the container starts.

What the container sees:

- The checkout (`git rev-parse --show-toplevel`) is bind-mounted at **the same absolute path as on the host** (canonical, i.e. with symlinks resolved) and is the working directory. Host paths therefore stay valid inside the container, and so do the absolute `gitdir:` pointers of linked git worktrees (`git worktree add`), whose main `.git` directory is bind-mounted at its host path as well. Nothing is mounted at `/ic`.
- The container user matches the host uid: `ubuntu` (1000, home `/home/ubuntu`) or `buildifier` (1001, home `/home/buildifier`). Any other uid falls back to `root` with a warning; files created by the container are then root-owned.
- `~/.cache` (or the directory given with `-c`/`--cache-dir`) is mounted at the container user's `~/.cache`. It holds bazel's output_user_root (output bases, install base, repository cache) and persists across containers. `~/.aws`, `~/.ssh` and `~/.claude` are mounted into the container user's home too, and the ssh agent socket is forwarded if one is running.
- On a devenv, `~/.gitconfig` and the shell history files are mounted as well and `CARGO_TARGET_DIR` is set to `~/.cache/cargo`.
- Extra `podman run`/`docker run` arguments come from `~/.container-run.conf` (see below).

### How to use custom config

User can create config `$HOME/.container-run.conf`, with `podman run` arguments, that provide way of adding custom bind-mounts etc. Config file requires array variable `PODMAN_RUN_USR_ARGS` with arguments accepted by `podman run` (see `podman run --help`). The same arguments are passed to `docker run` when `CONTAINER_RUNTIME=docker`, so keep them runtime-neutral, or guard them inside the file on the script's `$RUNTIME` variable (`podman` or `docker`; the file is sourced by `container-run.sh` with `set -u` in effect, and `CONTAINER_RUNTIME` itself may be unset), e.g. `if [ "$RUNTIME" = docker ]; then PODMAN_RUN_USR_ARGS+=(...); fi`. See example config from `.container-run.conf` below:

```bash
PODMAN_RUN_USR_ARGS=(
    --mount type=bind,source=${HOME}/dev,target=/home/ubuntu/dev
    --mount type=bind,source=${HOME}/.config/fish,target=/home/ubuntu/.config/fish
    -e TESTVARIABLE="something-i-expect"
)
```

### Running containers from several checkouts (git worktrees, clones) at once

Bazel derives its default output base from the workspace path: `~/.cache/bazel/_bazel_<user>/<md5 of the workspace path>`. Because the checkout is mounted at its host path, every checkout gets its own output base inside the container, while the install base, the repository cache and the repo contents cache (all under the shared `~/.cache/bazel/_bazel_<user>/`) are shared between checkouts. Containers started from different checkouts can run bazel concurrently.

This matters because bazel cannot recognize a server that runs in another container (each container has its own PID namespace): if two containers used the same output base, the second one would start another server in it and the first one would die with `Server terminated abruptly (error code: 14, ...)`.

Notes:

- Two containers started from the *same* checkout share an output base and must not run bazel at the same time. For a second shell in a running container use `sudo podman exec -it <container> bash` (on a devenv: `sudo podman --root /hoststorage/podman-root exec -it <container> bash`; with docker: `docker exec -it <container> bash`).
- The VS Code devcontainer (`.devcontainer/devcontainer.json`) mounts the checkout at its host path as well but pins its own output base, `~/.cache/bazel/_bazel_ubuntu/devcontainer-<id>`, through an rc file that its `initializeCommand` writes to `~/.cache/bazel/devcontainer/<id>.bazelrc` on the host and that `BAZELRC` points bazel at (`<id>` is the devcontainer's `${devcontainerId}`, unique per checkout). It therefore never collides with a `container-run.sh` container on the same checkout; the two do not share bazel build results, but they do share the install base, the repository cache and `~/.cache/cargo`. `bazel/bazel_clean.sh` removes all of this together with the rest of `~/.cache/bazel`.
- If your host user is `ubuntu` with uid 1000 or `buildifier` with uid 1001 (e.g. on the release verification VM) and you use the default cache directory, bazel on the host and bazel in a `container-run.sh` container use the same output base for a checkout; do not run them concurrently.
- `~/.cache/cargo` (`CARGO_TARGET_DIR` on devenvs and in the devcontainer) is shared between all checkouts; concurrent cargo builds serialize on its lock and invalidate each other's artifacts.
- Bazel creates its convenience symlinks (`bazel-bin`, `bazel-out`, `bazel-testlogs`, `bazel-<directory name of the checkout>`) in every checkout; they are gitignored.
- The first bazel run from a checkout after switching to this layout builds from scratch (the remote cache helps). Output bases from earlier layouts are no longer used and can be deleted once no container uses them: `~/.cache/bazel/_bazel_<user>/6d065581cce7ad9076e3b8db2b3afaf0` (the former shared base for `/ic`), `~/.cache/bazel/_bazel_<user>/<checkout directory name>-<8 hex digits>` and `~/.cache/container-run/`.

Linked git worktrees (`git worktree add`) are supported by `container-run.sh` (not by the devcontainer, whose mounts are static): the main repository's `.git` directory is bind-mounted at its host path so that git works inside the container. Inside a container `git worktree list` reports the *other* worktrees as `prunable` because their checkouts are not mounted, so never run `git worktree prune`, `repair`, `move` or `remove` inside a container; manage worktrees on the host. gc's automatic worktree pruning is disabled in every container (`container-run.sh` and the devcontainer) via `gc.worktreePruneExpire=never`.

To isolate everything, including the install base, repository cache and cargo target dir, use a separate cache directory instead (it is created if missing):

```bash
./ci/container/container-run.sh -c ~/.cache2
```

### Testing `container-run.sh`

`./ci/container/test-container-run.sh` starts a few containers from the current checkout and from a temporary linked worktree next to it and checks the mount layout, git, bazel's per-checkout output base (including that the main checkout's bazel server survives a bazel run from another checkout) and `build-ic.sh`. CI runs it once per container runtime; locally run it as is (podman) or with `CONTAINER_RUNTIME=docker`. It works on a dirty tree, uses a throwaway cache directory so it never touches your real output bases or running bazel servers, and cleans up after itself (a SIGKILL can leave a `<checkout>-test-wt.XXXXXX` directory behind).
