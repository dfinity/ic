In this directory you find scripts written to run various experiments against a testnet with IC OS tooling.

To work with testnets __you need a Linux machine__ (e.g., zh1-spm34.zh1.dfinity.network).

## Preparatory work with Nix

With nix-shell, you should invoke all commands with a nix-shell loaded from `./testnet/tests/scripts`.

For instance, the following can be used:
```
cd ./testnet/tests/scripts
nix-shell
[... run other commands ...]
```
## Preparatory work without Nix

Without Nix, you need to install some dependencies. For example, in Ubuntu you can run:
```
sudo bash -c "\
    apt purge -y ansible && \
    apt install -y python3-pip rclone csmith libcsmith-dev \
        gcc lld-10 clang-10 libc++-10-dev && \
    pip3 install ansible==2.10.7 pyyaml"
```

For the time being, you can use the following machine for testnet deployments, where are dependencies are already installed:

```
ssh -A zh1-spm34.zh1.dfinity.network
```

# Running

After installing the dependencies, you can run
```
./testnet/tools/icos_deploy.sh X --git-revision 809c4c02007f7ef93e2bb1db288c9fe2187bba7f
```

where `X` is the testnet you reserved, and the last part is a commit hash on master for which CI already built an image

To run the generic test which uses the latest available binaries you can call it as follows:

```
cd ./testnet/tests/scripts
./generic.sh "$TESTNET" 10 3 10 results
```

Some of the tests are run as part of CD nightly and hourly test runs, defined in link:../pipeline/pipeline.yml[`testnet/tests/pipeline/pipeline.yml`].

# Troubleshooting
List the inventory of a testnet
```
./testnet/env/<testnet>/hosts --list
```

To ssh into a node the user "admin" must be used.
```
ssh admin@<IPv6 address>
```

On a node, you can read the logs with
```
journalctl -u dfinity
```
