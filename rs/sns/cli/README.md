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

* You have downloaded and installed the [ic-cdk-optimizer](https://smartcontracts.org/docs/rust-guide/rust-optimize.html#_install_and_run_the_optimizer).

* You have installed [nix](https://nixos.org/manual/nix/stable/installation/installing-binary.html) and can run `nix-shell`.

### Local Deployment
`cd` into `rs/` and enter `nix-shell`:
```shell
nix-shell
```
`cd` into `rs/sns/cli/`. Remove state from past local deployments (if you want to do a clean local deploy)
```shell
make clean
```
In a separate tab (still in `rs/sns/cli/`), start a local Internet Computer network:
```shell
dfx start
```
Build `sns-cli` and the SNS canisters (skip this step if canisters and `sns-cli` are already built):
```shell
make
```

#### Barebones deploy
To deploy SNS locally without any customization (e.g. no initial ledger accounts), run:
```shell
sns deploy --token-name="My Example Token" --token-symbol="MET"
```
(assuming `sns` is in your `PATH`)

You should see the output of calls to `get_nervous_system_parameters` and `transfer_fee`, and see a 
"Successfully deployed!" message if the deployment was successful. 

If `sns` is not in your `PATH`, you can find it in `target`, e.g.
```shell
../../target/x86_64-apple-darwin/debug/sns
```

#### Deploy with initial Ledger accounts
To deploy SNS locally initial ledger accounts, you can run `deploy` with the `--initial-ledger-accounts` arg.
This arg takes a path to a file containing a JSON object that maps principal IDs to account values (in e8s). For 
example, such a file can be generated with:
```shell
echo "{\"$(dfx identity get-principal)\": 1000000000 }" > accounts.json
```
You can deploy an SNS with this account with:
```shell
sns deploy --token-name="My Example Token" --token-symbol="MET" --initial-ledger-accounts=accounts.json;
```
You can run `sns account-balance` to view your account balance.

There are other SNS parameters that can be customized, to view them run:
```shell
sns deploy --help
```

### IC Deployment
To deploy to the public Internet Computer (IC) network, `cd` into `rs/` and enter `nix-shell`:
```shell
cd rs;
nix-shell
```
cd to `rs/sns/cli` and build `sns` CLI and the SNS canisters (skip this step if canisters and `sns` CLI are already built):
```shell
cd sns/cli;
make
```
Ensure there are cycles in your cycles wallet. If you don't have any cycles, follow 
[these instructions](https://smartcontracts.org/docs/quickstart/4-quickstart.html) to acquire cycles. Choose a desired
amount of cycles to initialize each SNS canister with (here we choose 200B cycles), choose a token name and symbol, 
specify any optional params (e.g. initial ledger accounts) and call:
```shell
sns deploy --network ic --initial-cycles-per-canister 200000000000 --token-name="My Example Token" --token-symbol="MET" --initial-ledger-accounts=accounts.json;
```
