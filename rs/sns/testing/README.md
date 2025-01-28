# SNS testing

To run the scenario on the local PocketIC instance:
1) Launch PocketIC server: `bazel run //rs/pocket_ic_server:pocket-ic-server -- --ttl 6000 --port 8888`
2) Launch SNS testing scenario on it: `bazel run //rs/sns/testing:cli -- --server-url "http://127.0.0.1:8888"`

Open local NNS dapp instance: http://qoctq-giaaa-aaaaa-aaaea-cai.localhost:8080/proposals/?u=qoctq-giaaa-aaaaa-aaaea-cai.
You should be able to see executed proposals to add SNS WASM to SNS-W canisters (since currently used NNS dapp is slightly outdated, make sure to clear topic filters).

The scenario installs [test canister](./canister/canister.rs) and creates new SNS with it.
You should be able to see in NNS dapp web UI that the proposal to create a new SNS was adopted.

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
dfx canister --network pocket-ic-system call mxqf3-4h777-77775-qaaaa-cai greet "IC"
```

To get the latest NNS proposal info:
```
./dfx canister --network sns-testing call rrkah-fqaaa-aaaaa-aaaaq-cai list_proposals '(record { include_reward_status = vec {}; include_status = vec {}; exclude_topic = vec {}; limit = 1 })'
```
