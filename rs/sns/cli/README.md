# SNS CLI
`sns` is a command-line tool (CLI) that can be used to initialize, deploy and interact with an SNS (Service Nervous System)

## Local deployment
The following instructions will guide you through deploying a SNS locally.

### Prerequisites

Verify the following before deploying locally:

* You have installed the [Rust toolchain](https://www.rust-lang.org/learn/get-started) (e.g. cargo)

* You have downloaded and installed `dfx`, i.e. the [DFINITY Canister SDK](https://sdk.dfinity.org).

* You have stopped any Internet Computer or other network process that would
  create a port conflict on 8000.

* You have locally cloned the [ic](https://github.com/dfinity/ic) repo.

### Deployment
`cd` into `rs/sns/cli/`. Remove state from past local deployments
```text
make clean
```
In a separate tab, start a local replica:
```text
dfx start
```
Build `sns-cli` and the SNS canisters (skip this step if canisters and `sns-cli` are already built):
```text
make
```
Deploy SNS locally (assuming `sns` is in your `PATH`):
```text
sns local-deploy
```
You should see the output of calls to `get_nervous_system_parameters` and `transfer_fee`, and see a 
"Successfully deployed!" message if the deployment was successful. 

If `sns` is not in your `PATH`, you can find it in `target`, e.g.
```text
../../target/x86_64-apple-darwin/debug/sns
```
