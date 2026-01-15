# SNS testing

## Table of Contents

* [Prerequisites](#prerequisites)
* [Bootstrap the local sns-testing IC network](#bootstrap-the-local-sns-testing-ic-network)
* [Run the basic scenario](#run-the-basic-scenario)
* [Interact with SNS lifecycle](#interact-with-sns-lifecycle)

## Prerequisites

SNS testing CLI uses identities managed by `dfx`. Currently, the scenario requires a single developer
identity to submit NNS/SNS proposals.

We suggest creating dedicated identity to use with this scenario:
```
dfx identity new sns-testing --storage-mode=plaintext
```
Mind the `--storage-mode=plaintext` as it is required to have `.pem` files in the `dfx` directory on the disk.

The scenario was tested with `dfx` `0.24.3`.

`bazel` is required for building binaires from the IC monorepo.

All instructions from this README are supposed to be run from the root of `ic-sns-testing` crate (i.e. from `rs/sns/testing`).

The easiest way to setup the environment for `sns-testing` is to run
```
. scripts/env.sh
```
This command will build all required binaries, copy them to `bin/` directory, and
add `$PWD/bin` to `PATH`.

Instructions below assume that `PATH` was updated via `. scripts/env.sh` to include all required binaries.

## Bootstrap the local sns-testing IC network

This section explains how to bootstrap the local sns-testing IC network based on PocketIC.
Subsequent sections will be using this network.

To launch the network:
1) Launch PocketIC server:
   This command will launch the `pocket-ic-server` instance in the foreground, so this step has to be launched
   in a separate terminal window.
   ```
   pocket-ic-server --ttl 300 --port 8888
   ```
2) Bootstrap the NNS on the launched PocketIC instance:
   Note that we need to use `bazel run` despite invoking `. scripts/env.sh` previously because
   `sns-testing-init` requires env variables with paths to canister WASM modules to be set which is done
   by `bazel run`.
   ```
   bazel run //rs/sns/testing:sns-testing-init -- --server-url "http://127.0.0.1:8888" \
       --dev-identity sns-testing
   ```

Once these steps are completed, the PocketIC will expose the IC network HTTP endpoint on "http://127.0.0.1:8080".
`sns-testing` identity will be added as a controller to the NNS neuron with the majority voting power, so all NNS proposals made
by `sns-testing` identity will be automatically adopted.

Additionally, `sns-testing-init` will output the ID of the NNS neuron that should be used to create NNS proposals.
```
...
Use the following NNS neuron ID for further testing: 3912484856864073044
```

This is the preconfigured NNS neuron controlled by identity specified via `--dev-identity`, and it is expected to have a lot of voting power. This neuron ID will be used later to submit NNS proposals that get adapted right away.

`sns-testing-init` additionally installs NNS dapp and Internet Identity canisters with which you can interact
through their web UI:
* NNS dapp: http://qoctq-giaaa-aaaaa-aaaea-cai.localhost:8080
* Internet Identity: http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:8080

NNS dapp canister can be used to inspect the state of NNS/SNS proposals as well as SNS swaps.

You can add the following network config to `~/.config/dfx/networks.json` to simplify the newly created
network usage with `dfx`:
```
{
  "sns-testing": {
    "bind": "127.0.0.1:8080"
  }
}
```

To stop the network, stop the running `pocket-ic-server` process.

## Run the basic scenario

This section is dedicated to running a basic non-interactive scenario that goes through the SNS lifecycle:
SNS creation, SNS swap completion, and SNS-controller canister upgrade.

This scenario uses hard-coded SNS configuration. To create and test user-defined SNS, please refer to
the [next section](#interact-with-sns-lifecycle).

Instructions below are based on the [test canister](./canister/canister.rs), feel free to use your own canister
providing corresponding changes to arguments.

To run the basic scenario on the local IC network instance:
1) Build and deploy canister that will be controlled by the created SNS:
   ```
   bazel build //rs/sns/testing:sns_testing_canister
   NNS_ROOT="r7inp-6aaaa-aaaaa-aaabq-cai"
   dfx canister \
       --network http://127.0.0.1:8080 \
       --identity sns-testing \
       create test \
       --controller "$NNS_ROOT" \
       --controller sns-testing \
       --no-wallet
   dfx canister \
        --network http://127.0.0.1:8080 \
        --identity sns-testing \
        install test \
        --wasm "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz"
   ```
2) Launch the basic SNS testing scenario:
   ```
   sns-testing --network http://127.0.0.1:8080 run-basic-scenario \
      --dev-identity sns-testing --nns-neuron-id 3912484856864073044 \
      --canister-id "$(dfx canister --network http://127.0.0.1:8080 id test)" \
      --upgrade-wasm-path "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz" \
      --upgrade-candid-arg '(record { greeting = "Hi" })'
   ```

You can run the basic scenario multiple times on the same IC network created by `sns-testing-init`.
To re-run it, remove `$PWD/.dfx` directory to be able to re-deploy the canister with the same name.

## Interact with SNS lifecycle

This section provides a step-by-step guide on how to deploy a user-defined SNS and interact with it during its lifecycle.

### Getting ICP tokens

You can use `sns-testing --network http://127.0.0.1:8080 transfer-icp` to get ICP tokens to your account.

This subcommand supports transfer to the direct account ID, e.g.:
```
sns-testing --network http://127.0.0.1:8080 transfer-icp --amount 650.0 --to 5c9b28f3e2218975ea76449cf9b949a860d741a3af7dd4dd062f7481e3a99cde
```

Or to the principal by its ID (and optionally subaccount):
```
sns-testing --network http://127.0.0.1:8080 transfer-icp --amount 650.0 --to-principal fomoo-4i5fe-epl6n-dc7hi-lfqhi-4ii4q-txsav-xvenw-ffacw-youhl-mae
```

Obtained ICP tokens can be used to buy cycles, participate in SNS swap or you may stake them to get NNS neuron. This can be done either using `dfx`, `quill` or NNS dapp web UI.

### Deploying user-provided SNS and completing the SNS swap

The suggested way to do deploy the new SNS is to use the [`sns` CLI](../cli/README.md) `propose` command. For more information please refer to the [documentation](https://internetcomputer.org/docs/building-apps/governing-apps/launching/launch-steps-1proposal#3-submit-nns-proposal-to-create-sns).

Make sure to use `sns-testing` identity when creating the proposal, so that it gets instantly adopted.

<details>
<summary>Sample SNS proposal creation workflow</summary>
<br>

The example will use `//rs/sns/testing:sns_testing_canister` canister as SNS-controlled canister and will base on the [init YAML file from SNS CLI](../cli/test_sns_init_v2.yaml).

**While using a custom sns_init.yaml file, make sure to set `start_time: null` in the swap parameters to ensure that the swap starts right away after the NNS proposal is executed.**

0) Copy the SNS init YAML to the local directory
   ```
   cp ../cli/test_sns_init_v2.yaml sns_init.yaml
   cp ../cli/test.png .
   ```

1) Build and deploy `test` canister:
   ```
   bazel build //rs/sns/testing:sns_testing_canister
   NNS_ROOT="r7inp-6aaaa-aaaaa-aaabq-cai"
   dfx canister \
       --network http://127.0.0.1:8080 \
       --identity sns-testing \
       create test \
       --controller "$NNS_ROOT" \
       --controller sns-testing \
       --no-wallet
   dfx canister \
        --network http://127.0.0.1:8080 \
        --identity sns-testing \
        install test \
        --wasm "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz"
   ```

2) Adjust init YAML file (you will need [`yq`](https://github.com/mikefarah/yq) to be installed to do this):
   ```
   # Add deployed test canister to the list of SNS-controlled canisters
   yq -i ".dapp_canisters |= [\""$(dfx canister --network http://127.0.0.1:8080 id test)"\"]" sns_init.yaml
   # Add neuron controlled by 'sns-testing' identity principal
   yq -i ".Distribution.Neurons[0].principal |= \""$(dfx identity get-principal --identity sns-testing)"\"" sns_init.yaml
   # Make the swap start right away after the NNS proposal is executed
   yq -i ".Swap.start_time |= null" sns_init.yaml
   ```

3) Propose to create the new SNS:
   ```
   # sns doesn't support CLI-provided identities despite '--identity' option
   dfx identity use sns-testing
   sns propose --network http://127.0.0.1:8080 --neuron-id 3912484856864073044 "$PWD/sns_init.yaml"
   ```

4) Complete the swap for the newly created SNS
   ```
   SNS_NAME="$(yq -r .name sns_init.yaml)"
   sns-testing --network http://127.0.0.1:8080 swap-complete --sns-name "$SNS_NAME"
   ```
</details>

Once the NNS proposal to create the new SNS is adopted and executed, the SNS swap is supposed to open.

You can participate in the swap using NNS dapp web UI by creating a new identity via Internet Identity and transferring
some ICP to the newly created account via `sns-testing transfer-icp` command.

Use `sns-testing swap-complete` to generate swap participations and complete the swap:
```
SNS_NAME="$(yq -r .name <Path to SNS YAML>)"
sns-testing --network http://127.0.0.1:8080 swap-complete \
    --sns-name "$SNS_NAME" \
    --follow-principal-neurons "$(dfx identity get-principal --identity sns-testing)"
```

This command will generate required number of participations with the sufficient amount of direct participants to complete the swap.

This command has optional `--follow-principal-neurons` and `--follow-neuron` arguments that accept `PrincipalId` and `NeuronId` to make swap
participant neurons follow given neurons.

### Upgrading SNS-controlled canister via SNS voting

The suggested way to submit SNS proposals is to use [`quill`](https://github.com/dfinity/quill/), for more info please refer to the [official documentation](https://internetcomputer.org/docs/building-apps/governing-apps/managing/making-proposals/).

It's required to set `IC_URL="http://127.0.0.1:8080"` env variable for `quill` and use `--insecure-local-dev-mode` `quill` option
to be able to use `quill` with network created by `sns-testing`.

<details>
<summary>Sample SNS-controlled canister upgrade workflow</summary>
<br>

At this point we assume that SNS named "Daniel" was created and its swap was successfully completed
by following "Sample SNS proposal creation workflow" steps from the [previous section](#deploying-user-provided-sns-and-completing-the-sns-swap).

1) Get SNS neuron ID contolled by `sns-testing` identity:
   ```
   IC_URL="http://127.0.0.1:8080" quill sns neuron-id --principal-id "$(dfx identity get-principal --identity sns-testing)" --memo 42
   ```

   ```
   SNS Neuron Id: a96c889f2eab3fb4ae7aac3978f04eeb039e0ec8047516fcd8fae8b20bd75502
   ```
   This neuron ID will be used in step 3.

2) Prepare `sns_canister_ids.json`

   Get SNS canister IDs:
   ```
   IC_URL="http://127.0.0.1:8080" quill --insecure-local-dev-mode sns list-deployed-snses
   ```

   ```
   cat >> sns_canister_ids.json<< EOF
   {
      "root_canister_id":"7tjcv-pp777-77776-qaaaa-cai",
      "governance_canister_id":"7uieb-cx777-77776-qaaaq-cai",
      "index_canister_id":"7pnye-yp777-77776-qaaca-cai",
      "swap_canister_id":"72kjj-zh777-77776-qaabq-cai",
      "ledger_canister_id":"75lp5-u7777-77776-qaaba-cai"
   }
   EOF
   ```

   SNS canister IDs may vary for you.

3) Prepare quill `message.json` with SNS-controlled canister upgrade proposal:
   ```
   quill sns --pem-file ~/.config/dfx/identity/sns-testing/identity.pem --canister-ids-file sns_canister_ids.json make-upgrade-canister-proposal \
      --target-canister-id lxzze-o7777-77777-aaaaa-cai --wasm-path "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz" \
      --title "Upgrade SNS-controlled-canister" --mode upgrade "<Neuron ID>" > message.json
   ```

4) Submit the message with SNS proposal:
   ```
   IC_URL="http://127.0.0.1:8080" quill --insecure-local-dev-mode send message.json
   ```

   This command will return the ID of the newly created proposal
   ```
   ...
   Successfully created new proposal with ID 1
   ```
   The ID of the proposal will be used in the next step.

5) Upvote the proposal and wait for its execution:
   ```
   sns-testing --network http://127.0.0.1:8080 sns-proposal-upvote --sns-name "$SNS_NAME" --proposal-id 1 --wait
   ```

</details>

Once the SNS proposal is created, the voting begins.
To upvote the proposal using Neurons controlled by identities that participated in the swap on the [previous steps](#deploying-user-provided-sns-and-completing-the-sns-swap) run:
```
sns-testing --network http://127.0.0.1:8080 sns-proposal-upvote --sns-name "<SNS name>" --proposal-id "<Proposal ID>" --wait
```
