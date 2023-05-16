# Container Dev & Build Environment

Codebase for containerized build and development environment.
<br>
See [Dockerfile](Dockerfile) for info about required dependencies.

## Requirements

- x86-64 based system (at least 8 CPUs, 16 GB MEM/SWAP, 100 GB available disk space)
- Ubuntu 20.04 or newer
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
$ ./gitlab-ci/container/build-ic.sh -i
$ # artifacts are available under ./artifacts directory
$ tree artifacts/
```

*Note:* This implies building binaries and canisters as IC-OS requires them.

## Building Binaries or Canisters

Only binaries:

```bash
$ ./gitlab-ci/container/build-ic.sh -b
$ # artifacts are available under ./artifacts/binaries directory
$ ls -l artifacts/binaries
```

Only canisters:

```bash
$ ./gitlab-ci/container/build-ic.sh -c
$ # artifacts are available under ./artifacts/canisters directory
$ ls -l artifacts/canisters
```

Both binaries and canisters:

```bash
$ ./gitlab-ci/container/build-ic.sh -b -c
```
