# Tools to run static testnets

## Running a static testnet from the local build

The procedure currently works on a linux host only.

* Reserve a static testnet using Dee
* Start the container: `./gitlab-ci/container/container-run.sh`
* Produce required artifacts and start the testnet reserved using them: `bazel run //testnet/tools:icos_deploy --config=systest -- <testnet>`

To produce all required artifacts but do not start a testnet run the command with `-n` flag: `bazel run //testnet/tools:icos_deploy --config=systest -- -n`
