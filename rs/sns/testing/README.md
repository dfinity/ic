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
bazel build //rs/sns/testing:cli
bazel build //rs/sns/testing:sns_testing_canister
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
   bazel run //rs/sns/testing:cli -- nns-init --server-url "http://127.0.0.1:8888" --state-dir "$PWD/sns-testing" --dev-identity sns-testing
   ```
3) Build and deploy `test` canister:
   ```
   # 'r7inp-6aaaa-aaaaa-aaabq-cai' is the NNS Root canister
   dfx canister --network http://127.0.0.1:8080 --identity sns-testing create test --controller r7inp-6aaaa-aaaaa-aaabq-cai --controller sns-testing --no-wallet
   dfx canister --network http://127.0.0.1:8080 --identity sns-testing install test --wasm "$(bazel info bazel-bin)/rs/sns/testing/sns_testing_canister.wasm.gz"
   ```
4) Launch the basic SNS testing scenario:
   ```
   bazel run //rs/sns/testing:cli -- run-basic-scenario --network http://127.0.0.1:8080 \
     --dev-identity sns-testing \
     --test-canister-id "$(dfx canister --network http://127.0.0.1:8080 id test)"
   ```

To start the scenario from scratch, you'll need to stop the running `pocket-ic-server` instance and
remove `$PWD/sns-testing` and `$PWD/.dfx` directories before doing the steps mentioned above.

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


