# SNS testing

To run the scenario on the local PocketIC instance:
1) Launch PocketIC server: `bazel run //rs/pocket_ic_server:pocket-ic-server -- --ttl 6000 --port 8888`
2) Launch SNS testing scenario on it: `bazel run //rs/sns/testing:cli -- --server-url "http://127.0.0.1:8888"`

Open local NNS dapp instance: http://qoctq-giaaa-aaaaa-aaaea-cai.localhost:8080/proposals/?u=qoctq-giaaa-aaaaa-aaaea-cai.
You should be able to see executed proposals to add SNS WASM to SNS-W canisters (since currently used NNS dapp is slightly outdated, make sure to clear topic filters).
