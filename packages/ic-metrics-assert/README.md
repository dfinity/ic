# IC Metrics Assert

> Fluent assertions for Prometheus-style metrics exposed by Internet Computer (IC) canisters.

`ic-metrics-assert` provides regex-based assertions for testing metrics endpoints of IC canisters. It supports both synchronous and asynchronous contexts, and integrates with [`PocketIc`](https://docs.rs/pocket-ic) for local canister testing.

## Features

- Query metrics from canister `/metrics` HTTP endpoint
- Fluent regex-based assertions on canister metrics
- Support for both sync and async test flows
- Optional `pocket_ic` feature for use with `PocketIc` environments
