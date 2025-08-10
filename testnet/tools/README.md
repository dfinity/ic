# Tools to run static testnets

## Running a static testnet from the local build

The procedure currently works on a linux host only.

* Reserve a static testnet using Dee
* Build and deploy IC-OS to static testnet
  ```bash
  ./ci/container/container-run.sh -f
  export ANSIBLE_REMOTE_USER=<sshuser>
  bazel run //testnet/tools:icos_deploy --config=testnet -- <testnet>
  ```

**Note:** *It's important that sshuser matches with your username that was set on servers that run tesetnet nodes! See [here](https://github.com/dfinity-lab/dcs/blob/master/ansible-internal/group_vars/development.yml).*

To produce all required artifacts but do not start a testnet run the command with `-n` flag:
```bash
bazel run //testnet/tools:icos_deploy --config=testnet -- -n
```
