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

Script `container-run.sh` creates a rootful podman container with various arguments as seen below.

```bash
sudo podman run --pids-limit=-1 -it --rm --privileged --network=host --cgroupns=host -w /ic \
  -u 1000:1001 -e HOSTUSER=john -e VERSION=8bb1564701c56424f77f16ef067599a1c1dc7c37 \
  --hostname=devenv-container --add-host devenv-container:127.0.0.1 \
  --entrypoint= --init --hostuser=john \
  --mount type=tmpfs,destination=/var/sysimage \
  --mount type=bind,source=/home/john/dev/ic-ctr-run-usr-cfg,target=/ic \
  --mount type=bind,source=/home/john,target=/home/john \
  --mount type=bind,source=/home/john /.cache,target=/home/ubuntu/.cache \
  --mount type=bind,source=/home/john/.ssh,target=/home/ubuntu/.ssh \
  --mount type=bind,source=/home/john/.aws,target=/home/ubuntu/.aws \
  --mount type=bind,source=/var/lib/containers,target=/var/lib/containers \
  --mount type=bind,source=/home/john/.gitconfig,target=/home/ubuntu/.gitconfig \
  --mount type=bind,source=/home/john/.bash_history,target=/home/ubuntu/.bash_history \
  --mount type=bind,source=/home/john/.local/share/fish,target=/home/ubuntu/.local/share/fish \
  --mount type=bind,source=/home/john/.zsh_history,target=/home/ubuntu/.zsh_history \
  -v /tmp/ssh-XXXXQAO7kF/agent.113731:/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent -w /ic \
  docker.io/dfinity/ic-build:221b79c4f4a966eae67a3f9ef7f20f4c5583d5bc38df17c94128804687a84c29 /usr/bin/fish
```

### How to use custom config

User can create config `$HOME/.container-run.conf`, with `podman run` arguments, that provide way of adding custom bind-mounts etc. Config file requires array variable `PODMAN_RUN_USR_ARGS` with arguments accepted by `podman run` (see `podman run --help`). See example config from `.container-run.conf` below:

```bash
PODMAN_RUN_USR_ARGS=(
    --mount type=bind,source=${HOME}/dev,target=/home/ubuntu/dev
    --mount type=bind,source=${HOME}/.config/fish,target=/home/ubuntu/.config/fish
    -e TESTVARIABLE="something-i-expect"
)
```

### How to run parallel bazel tests

By default `container-run.sh` bind-mounts `~/.cache` which is used for (output_base)[https://bazel.build/docs/user-manual#output-base]. If you need to run 2nd build/test in parallel but not interfere with the 1st one, follow the steps below.

```bash
mkdir ~/.cache2
./ci/container/container-run.sh -c ~/.cache2
```
