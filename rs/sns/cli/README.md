# SNS CLI

## Overview
`sns` is a command-line tool (CLI) that can be used to initialize, deploy and interact with an SNS (service nervous system). 

## Table of Contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How-To](#how-to)
- [Glossary](#glossary)


## Requirements
- You have downloaded and installed `dfx`, i.e. the [DFINITY Canister SDK](https://internetcomputer.org/docs/current/developer-docs/getting-started/install/).

## Installation

There are two recommended ways to install the `sns` CLI to your system:

1. Use the bundled version of the CLI available in `dfx`. The `dfx sns` subcommand should be available in `dfx-0.13.0` and up. You can see your current `dfx` version and upgrade it by running the following commands:

```shell
dfx --version
dfx upgrade
```

**Note**: The version of the `sns` CLI that is bundled with your `dfx` version may not have the latest commands described in the [Usage](#usage) section. If needed, it is recommended to build and use the `sns` CLI tool yourself.  

2. Build the `sns` CLI binary yourself from the main [ic monorepo](https://github.com/dfinity/ic). Instructions to install the required build tool `bazel` can be found at [bazel.build](https://bazel.build/install/bazelisk). Once installed, execute the following commands to build:

```shell
git clone git@github.com:dfinity/ic.git
cd ic
bazel build //rs/sns/cli:sns
ls bazel-bin/rs/sns/cli/sns 
```

This will build the binary at this location `bazel-bin/rs/sns/cli/sns`, which should be moved to somewhere in your executable path (see `$PATH`).


## Usage
The following instructions will guide you through deploying an SNS.

To run the binary, simply use the command `sns` followed by the required arguments:

```shell
sns [OPTIONS] [SUBCOMMAND]
```

### Options

- `-h, --help`: Prints help information
- `-V, --version`: Prints the sns CLI version information

### Subcommands

- `init-config-file`: Subcommand that creates and validates configuration files 
- `deploy`: Subcommand that deploys an SNS based on a configuration file
- `deploy-test-flight` : Subcommand that deploys an SNS based on a configuration file in testflight mode
- `help`: Subcommand that prints help information 

For detailed information about each subcommand, use the following command:

```shell
sns [SUBCOMMAND] --help
```

## How-To

### Creating The Configuration File

To create an SNS either locally or on IC mainnet, one must configure the initial parameters. The parameters are passed to the CLI tool in a _yaml_ file. The subcommand `init-config-file`  is used to create and validate this file.

To create a default _yaml_ configuration file run the following command:

```shell
sns init-config-file new
```

This creates a new template file, by default with the name *sns_init.yaml*, that contains the necessary parameters with comments. Most parameters are filled in with sensible defaults while some must be filled in by the developer.

To see if the values you've provided are valid, use the following command to run local validation. The same validation will be applied within the SNS-W canister when deploying the SNS.

```shell
sns init-config-file validate
```

If you renamed your configuration file, use the `--init-config-file-path` option.

```shell
sns init-config-file --init-config-file-path <path_to_config_file> validate
```

If you are interested in testing your SNS, follow the instructions for [local testing](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/get-sns/local-testing) and using [SNS testflight](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/get-sns/testflight).

### Deploying An SNS

If you are interested in testing your SNS, make sure you follow the instructions for [local testing](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/get-sns/local-testing). Once the configuration file has been filled out and validated, you are ready to deploy an SNS. To deploy either locally, or to mainnet, one must have a wallet that is whitelisted as an authorized principal in the SNS-W canister of the NNS. See the [SNS developer docs](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/lifecycle-sns/sns-launch) for more details. 

Additionally, deploying an SNS requires cycles, currently 180TC. The `sns` CLI will use the default wallet configured with your dfx identity to transfer the cycles and the wallet canister id must match the whitelisted principal of the above step. 

Assuming this step is complete, and the `sns` binary is on your executable path (check out environment variable `$PATH`), use the `deploy` subcommand to read the configuration file, and then generate and send the required payload to the SNS-W canister.

```shell
sns deploy --network <NETWORK> --init-config-file <INIT_CONFIG_FILE>
```

Where `<NETWORK>` is the dfx network you'd like to deploy to. For example, to deploy to mainnet:

```shell
sns deploy --network ic --init-config-file sns_init.yaml 
```

To deploy locally:

```shell
sns deploy --network local --init-config-file sns_init.yaml
```

There are other flags that can be used during deployment, to view them run:
```shell
sns deploy --help
```

### Testflight An SNS

If you are interested in testing your SNS, make sure you follow the instructions for using [SNS testflight](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/get-sns/testflight).Before launching an SNS on mainnet, you are encouraged to test your mainnet dapp's operation (e.g., upgrading the dapp's canisters) via SNS proposals.

You can test SNS proposals by deploying a testflight SNS and submitting SNS proposals to it. The main differences to production SNS deployment are:
- A testflight SNS is deployed by the developer instead of NNS; in particular, no NNS proposals are involved.
- No decentralization swap is performed; in particular, the developer has full control over the SNS for the entire duration of the testflight.
- The developer keeps direct control over the dapp's canisters registered with testflight SNS (otherwise, it'd be tricky to regain control over the canister after the testflight is finished).
- When deployed on the mainnet, testflight SNS is deployed to a regular application subnet instead of a dedicated SNS subnet.
- There are no "real tokens" minted with the testflight.

To deploy a testflight SNS, run the following command:

```shell
sns deploy-testflight --network <NETWORK> --init-config-file <INIT_CONFIG_FILE>
```

Where `<NETWORK>` is the dfx network you'd like to deploy to.

## Glossary

- **[dfx](https://internetcomputer.org/docs/current/developer-docs/setup/install)**: The DFINITY command-line execution environment (dfx) is the primary tool for creating, deploying, and managing the dapps for the Internet Computer platform.
- **[SNS](https://internetcomputer.org/sns)**: A Service Nervous Systems (SNS) is an advanced form of a DAO. A digital democracy that can run any dapp such as a social network in a fully decentralized way, fully on chain.
- **[NNS](https://internetcomputer.org/nns)**: The NNS is one of the world's largest DAOs that governs the Internet Computer. It is a 100% on-chain, permissionless system that continuously upgrades the Internet Computer based on the voting of ICP token holders.
- **SNS-W Canister**: An NNS canister that deploys an SNS to the protected SNS subnet and stores the latest versions of the SNS canisters.
- **SNS Testflight**: A "test" version of the SNS where the dapp developer is always in full control of their dapp.
