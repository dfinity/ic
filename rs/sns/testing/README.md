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
   bazel run //rs/sns/testing:sns-testing-init -- \
       --server-url "http://127.0.0.1:8888" \
       --state-dir "$PWD/sns-testing" \
       --dev-identity sns-testing \
       --deciding-nns-neuron-id 1
   ```
3) Build and deploy `test` canister:
   ```
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
4) Launch the basic SNS testing scenario:
   ```
   bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 run-basic-scenario \
      --dev-identity sns-testing --nns-neuron-id 1 \
      --test-canister-id "$(dfx canister --network http://127.0.0.1:8080 id test)" \
      --upgrade-wasm-path "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz" \
      --upgrade-candid-arg '(record { greeting = "Hi" })'
   ```

To start the scenario from scratch, you'll need to stop the running `pocket-ic-server` instance and
remove `$PWD/sns-testing` and `$PWD/.dfx` directories before doing the steps mentioned above.

## Get ICP tokens

You can use `bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 transfer-icp` to get ICP tokens to your account.

This subcommand supports transfer to the direct account ID, e.g.:
```
bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 transfer-icp --amount 650.0 --to 5c9b28f3e2218975ea76449cf9b949a860d741a3af7dd4dd062f7481e3a99cde
```

Or to the principal by its ID (and optionally subaccount):
```
bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 transfer-icp --amount 650.0 --to-principal fomoo-4i5fe-epl6n-dc7hi-lfqhi-4ii4q-txsav-xvenw-ffacw-youhl-mae
```

Obtained ICP tokens can be used to participate in SNS swap or you may stake them to get NNS neuron. This can be done either using `quill` or NNS dapp web UI.

## Deploying user-provided SNS

### Bootstrap the network

1) Launch PocketIC server:
   ```
   bazel run //rs/pocket_ic_server:pocket-ic-server -- --ttl 6000 --port 8888
   ```

2) Bootstrap the NNS on the launched PocketIC instance:
   ```
   bazel run //rs/sns/testing:sns-testing-init -- \
       --server-url "http://127.0.0.1:8888" \
       --state-dir "$PWD/sns-testing" \
       --dev-identity sns-testing \
       --deciding-nns-neuron-id 1
   ```

Once these steps are completed, the PocketIC will expose the IC network HTTP endpoint on "http://127.0.0.1:8080".
`sns-testing` identity will be added as a hotkey to the NNS neuron with the majority voting power, so all NNS proposals made
by `sns-testing` will be automatically adopted.

Additionally, `sns-testing-init` will output the ID of the NNS neuron that should be used to create NNS proposals.
```
...
Use the following NNS neuron ID for further testing: 1
```

### Create the new SNS

Now you can create a new SNS via NNS proposal.

The suggested way to do this is to use `dfx sns propose` command. For more information please refer to the [documentation](https://internetcomputer.org/docs/building-apps/governing-apps/launching/launch-steps-1proposal#3-submit-nns-proposal-to-create-sns).

Make sure to use `sns-testing` identity when creating the proposal, so that it gets instantly adopted.

<details>
<summary>Sample SNS proposal creation workflow</summary>
<br>

The example will use `//rs/sns/testing:sns_testing_canister` canister as SNS-controlled canister and will base on the [init YAML file from SNS CLI](../cli/test_sns_init_v2.yaml).

**While using a custom sns_init.yaml file, make sure to set `start_time: null` in the swap parameters to ensure that the swap starts right away after the NNS proposal is executed.**

0) Copy the SNS init YAML to the local directory
   ```
   cp ../cli/test_sns_init_v2.yaml sns_init.yaml
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
   yq -i ".dapp_canisters |= [\""$(dfx canister --network http://127.0.0.1:8080 id test)"\"]" sns_init.yaml
   yq -i ".Distribution.Neurons[0].principal |= \""$(dfx identity get-principal --identity sns-testing)"\"" sns_init.yaml
   yq -i ".Swap.start_time |= null" sns_init.yaml
   ```

3) Propose to create the new SNS:
   ```
   # //rs/sns/cli:sns doesn't support CLI-provided identities despite '--identity' option
   dfx identity use sns-testing
   bazel run //rs/sns/cli:sns -- propose --network http://127.0.0.1:8080 --neuron-id 1 "$PWD/sns_init.yaml"
   ```

4) Complete the swap for the newly created SNS
   ```
   SNS_NAME="$(yq -r .name sns_init.yaml)"
   bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 swap-complete --sns-name "$SNS_NAME"
   ```
</details>

Once the NNS proposal to create the new SNS is adopted and executed, the SNS swap is supposed to open.

You can participate in the swap using NNS dapp web UI by creating a new identity via Internet Identity and transferring
some ICP to the newly created account via `sns-testing transfer-icp` command.

Use `bazel run //rs/sns/testing:cli -- run swap-complete` to generate swap participations and complete the swap:
```
SNS_NAME="$(yq -r .name <Path to SNS YAML>)"
bazel run //rs/sns/testing:sns-testing -- \
    --network http://127.0.0.1:8080 \
    swap-complete \
    --sns-name "$SNS_NAME" \
    --follow-principal-neurons "$(dfx identity get-principal --identity sns-testing)"
```

This command will generate required number of participations with the sufficient amount of direct participants to complete the swap.

This command has optional `--follow-principal-neurons` and `--follow-neuron` arguments that accept `PrincipalId` and `NeuronId` to make swap
participant neurons follow given neurons.

### SNS voting

The newly created SNS is now fully functional and is ready for proposals.

The suggested way to submit SNS proposals is to use [`quill`](https://github.com/dfinity/quill/), for more info please refer to the [official documentation](https://internetcomputer.org/docs/building-apps/governing-apps/managing/making-proposals/).

It's required to set `IC_URL="http://127.0.0.1:8080"` env variable for `quill` and use `--insecure-local-dev-mode` `quill` option
to be able to use `quill` with network created by `sns-testing`.

<details>
<summary>Sample SNS-controlled canister upgrade workflow</summary>
<br>

At this point we assume that SNS named "Daniel" was created and its swap was successfully completed.

1) Get SNS neuron ID contolled by `sns-testing` identity:
   ```
   IC_URL="http://127.0.0.1:8080" quill sns neuron-id --principal-id "$(dfx identity get-principal --identity sns-testing)" --memo 42
   ```

   ```
   SNS Neuron Id: a96c889f2eab3fb4ae7aac3978f04eeb039e0ec8047516fcd8fae8b20bd75502
   ```

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

</details>

Once the SNS proposal is created, the voting begins.
To upvote the proposal using Neurons controlled by identities that participated in the swap on the previous step run:
```
bazel run //rs/sns/testing:sns-testing -- --network http://127.0.0.1:8080 sns-proposal-upvote --sns-name "<SNS name>" --proposal-id "<Proposal ID>" --wait
```

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


