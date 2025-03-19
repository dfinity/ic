# SNS testing

## Prerequisites

SNS testing CLI uses identities managed by `dfx`. Currently, the scenario requires a single developer
identity to submit NNS/SNS proposals.

We suggest creating dedicated identity to use with this scenario:
```
dfx identity new sns-testing --storage-mode=plaintext
```
Mind the `--storage-mode=plaintext` as it is required to have `.pem` files in the `dfx` directory on the disk.

The scenario was tested with `dfx` `0.24.3`.

## Run the basic scenario

The scenario is supposed to be run from the root of `ic-sns-testing` crate (i.e. from `rs/sns/testing`).

Since `bazel` doesn't allow to run multiple tasks in parallel, it's recommended to build all required
targets before starting the scenario:
```
bazel build //rs/pocket_ic_server:pocket-ic-server
bazel build //rs/sns/testing/...
```

To run the scenario on the local PocketIC instance:
1) Launch PocketIC server:
   This command will launch the `pocket-ic-server` instance in the foreground, so this step has to be launched
   in a separate terminal window.
   ```
   bazel run //rs/pocket_ic_server:pocket-ic-server -- --ttl 300 --port 8888
   ```
2) Bootstrap the NNS on the launched PocketIC instance:
   ```
   bazel run //rs/sns/testing:sns-testing-init -- --server-url "http://127.0.0.1:8888" --state-dir "$PWD/sns-testing" --dev-identity sns-testing
   ```
3) Build and deploy `test` canister:
   ```
   # 'r7inp-6aaaa-aaaaa-aaabq-cai' is the NNS Root canister
   dfx canister --network http://127.0.0.1:8080 --identity sns-testing create test --controller r7inp-6aaaa-aaaaa-aaabq-cai --controller sns-testing --no-wallet
   dfx canister --network http://127.0.0.1:8080 --identity sns-testing install test --wasm "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz"
   ```
4) Launch the basic SNS testing scenario:
   ```
   bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 run-basic-scenario \
      --dev-identity sns-testing \
      --test-canister-id "$(dfx canister --network http://127.0.0.1:8080 id test)"
   ```

To start the scenario from scratch, you'll need to stop the running `pocket-ic-server` instance and
remove `$PWD/sns-testing` and `$PWD/.dfx` directories before doing the steps mentioned above.

## Deploying user-provided SNS

### Bootstrap the network

1) Launch PocketIC server:
   ```
   bazel run //rs/pocket_ic_server:pocket-ic-server -- --ttl 6000 --port 8888
   ```

2) Bootstrap the NNS on the launched PocketIC instance:
   ```
   bazel run //rs/sns/testing:sns-testing-init -- --server-url "http://127.0.0.1:8888" --state-dir "$PWD/sns-testing" --dev-identity sns-testing
   ```

Once these steps are completed, the PocketIC will expose the IC network HTTP endpoint on "http://127.0.0.1:8080".
`sns-testing` identity will be added as a hotkey to the NNS neuron with the majority voting power, so all NNS proposals made
by `sns-testing` will be automatically accepted.

Additionally, `nns-init` will output the ID of the NNS neuron that should be used to create NNS proposals.
```
...
Use the following Neuron ID for further testing: 449479075714955186
```

### Create the new SNS

Now you can create a new SNS via NNS proposal.

The suggested way to do this is to use `dfx sns propose` command. For more information please refer to the [documentation](https://internetcomputer.org/docs/building-apps/governing-apps/launching/launch-steps-1proposal#3-submit-nns-proposal-to-create-sns).

Make sure to use `sns-testing` identity when creating the proposal.

<details>
<summary>Sample SNS proposal creation workflow</summary>
<br>

The example will use `//rs/sns/testing:sns_testing_canister` canister as SNS-controlled canister and will base on the [init YAML file from SNS CLI](../cli/test_sns_init_v2.yaml).

**Make sure to use `start_time: null` in the swap parameters to ensure that the swap starts right away after the NNS proposal is executed.**

1) Build and deploy `test` canister:
   ```
   bazel build //rs/sns/testing:sns_testing_canister
   # 'r7inp-6aaaa-aaaaa-aaabq-cai' is the NNS Root canister
   dfx canister --network http://127.0.0.1:8080 --identity sns-testing create test --controller r7inp-6aaaa-aaaaa-aaabq-cai --controller sns-testing --no-wallet
   dfx canister --network http://127.0.0.1:8080 --identity sns-testing install test --wasm "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz"
   ```

2) Adjust init YAML file (you will need [`yq`](https://github.com/mikefarah/yq) to be installed to do this):
   ```
   yq -i ".dapp_canisters |= [\""$(dfx canister --network http://127.0.0.1:8080 id test)"\"]" ../cli/test_sns_init_v2.yaml
   yq -i ".Distribution.Neurons[0].principal |= \""$(dfx identity get-principal --identity sns-testing)"\"" ../cli/test_sns_init_v2.yaml
   yq -i ".Swap.start_time |= null" ../cli/test_sns_init_v2.yaml
   ```
3) Propose to create the new SNS:
   ```
   pushd ../cli
   # //rs/sns/cli:sns doesn't support CLI-provided identities despite '--identity' option
   dfx identity use sns-testing
   bazel run //rs/sns/cli:sns -- propose --network http://127.0.0.1:8080 --neuron-id 449479075714955186 $PWD/test_sns_init_v2.yaml
   popd
   ```

4) Complete the swap for the newly created SNS
   ```
   SNS_NAME="$(yq -r .name ../cli/test_sns_init_v2.yaml)"
   bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 swap-complete --sns-name "SNS_NAME"
   ```
</details>

Once the NNS proposal to create the new SNS is adopted and executed, the SNS swap is supposed to open.
Use `bazel run //rs/sns/testing:cli -- run swap-complete` to generate swap participations and complete the swap:
```
SNS_NAME="$(yq -r .name <Path to SNS YAML>)"
bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 swap-complete --sns-name "$SNS_NAME" --follow-principal-neurons "$(dfx identity get-principal --identity sns-testing)"
```

This command will generate required number of participations with the sufficient amount of direct participants to complete the swap.

This command has optional `--follow-principal-neurons` and `--follow-neuron` arguments that accept `PrincipalId` and `NeuronId` to make swap
participant neurons follow given neurons.

## Check the network state

Open local NNS dapp instance: http://qoctq-giaaa-aaaaa-aaaea-cai.localhost:8080/proposals/?u=qoctq-giaaa-aaaaa-aaaea-cai.
You should be able to see executed proposals to add SNS WASM to SNS-W canisters (since currently used NNS dapp is slightly outdated, make sure to clear topic filters).

The scenario installs [test canister](./canister/canister.rs) and creates new SNS with it.
Once the proposal is adopted, the scenario initiates the SNS swap and closes it by providing sufficient amount of ICP.
Once swap is completed, the test canister is upgraded via SNS voting.

NNS dapp should show the NNS proposal to create the new SNS as well as proposal in the newly created SNS to upgrade
the controlled canister.

To interact with the network created by `sns-testing` CLI, you should add the following network config to
`~/.config/dfx/networks.json`:
```
{
  "sns-testing": {
    "bind": "127.0.0.1:8080"
  }
}
```

Now you can call the testing canister by its id (note that the actual id may vary, make sure to check logs, or NNS proposal info in NNS dapp):
```
dfx canister --network sns-testing call "$(dfx canister --network sns-testing id test)" greet "IC"
```

To get the latest NNS proposal info:
```
./dfx canister --network sns-testing call rrkah-fqaaa-aaaaa-aaaaq-cai list_proposals '(record { include_reward_status = vec {}; include_status = vec {}; exclude_topic = vec {}; limit = 1 })'
```


