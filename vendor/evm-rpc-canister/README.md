# EVM RPC &nbsp;[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/internet-computer-protocol/evm-rpc-canister/issues)

> #### Interact with [EVM blockchains](https://chainlist.org/?testnets=true) from the [Internet Computer](https://internetcomputer.org/).

## Overview

**EVM RPC** is an Internet Computer canister smart contract for communicating with [Ethereum](https://ethereum.org/en/) and other [EVM blockchains](https://chainlist.org/?testnets=true) using an on-chain API. 

This canister facilitates API requests to JSON-RPC services such as [CloudFlare](https://www.cloudflare.com/en-gb/web3/), [Alchemy](https://www.alchemy.com/), [Ankr](https://www.ankr.com/), or [BlockPI](https://blockpi.io/) using [HTTPS outcalls](https://internetcomputer.org/https-outcalls). This enables functionality similar to traditional Ethereum dapps, including querying Ethereum smart contract states and submitting raw transactions.

Beyond the Ethereum blockchain, this canister also has partial support for Polygon, Avalanche, and other popular EVM networks. Check out [ChainList.org](https://chainlist.org/?testnets=true) for an extensive list of networks and RPC providers.

You can read more about the inner workings of the EVM RPC canister [here](https://medium.com/dfinity/icp-ethereum-how-icps-evm-rpc-canister-connects-the-networks-b57909efecf6).

## Documentation

You can find extensive documentation for the EVM RPC canister in the [ICP developer docs](https://internetcomputer.org/docs/current/developer-docs/multi-chain/ethereum/evm-rpc/overview).

## Canister

The EVM RPC canister runs on the [fiduciary subnet](https://internetcomputer.org/docs/current/concepts/subnet-types#fiduciary-subnets) with the following principal: [`7hfb6-caaaa-aaaar-qadga-cai`](https://dashboard.internetcomputer.org/canister/7hfb6-caaaa-aaaar-qadga-cai). 

Refer to the [Reproducible Builds](#reproducible-builds) section for information on how to verify the hash of the deployed WebAssembly module.

## Quick Start

Add the following to your `dfx.json` config file (replace the `ic` principal with any option from the list of available canisters above):

```json
{
  "canisters": {
    "evm_rpc": {
      "type": "custom",
      "candid": "https://github.com/internet-computer-protocol/evm-rpc-canister/releases/latest/download/evm_rpc.did",
      "wasm": "https://github.com/internet-computer-protocol/evm-rpc-canister/releases/latest/download/evm_rpc.wasm.gz",
      "remote": {
        "id": {
          "ic": "7hfb6-caaaa-aaaar-qadga-cai"
        }
      },
      "init_arg": "(record {})"
    }
  }
}
```

Run the following commands to deploy the canister in your local environment:

```sh
# Start the local replica
dfx start --background

# Locally deploy the `evm_rpc` canister
dfx deploy evm_rpc --argument '(record {})'
```

The EVM RPC canister also supports [`dfx deps pull`](https://internetcomputer.org/docs/current/references/cli-reference/dfx-deps). Add the following to your `dfx.json` file:

```json
{
  "canisters": {
    "evm_rpc": {
      "type": "pull",
      "id": "7hfb6-caaaa-aaaar-qadga-cai"
    }
  }
}
```

Next, run the following commands:

```sh
# Start the local replica
dfx start --background

# Locally deploy the `evm_rpc` canister
dfx deps pull
dfx deps init evm_rpc --argument '(record {})'
dfx deps deploy
```

## Examples

### JSON-RPC (IC mainnet)

```bash
dfx canister call evm_rpc request '(variant {Chain=0x1},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)' --wallet $(dfx identity get-wallet --ic) --with-cycles 1000000000 --ic
```

### JSON-RPC (local replica)

```bash
# Use a custom provider
dfx canister call evm_rpc request '(variant {Custom=record {url="https://cloudflare-eth.com"}},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)' --wallet $(dfx identity get-wallet) --with-cycles 1000000000
dfx canister call evm_rpc request '(variant {Custom=record {url="https://ethereum.publicnode.com"}},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)' --wallet $(dfx identity get-wallet) --with-cycles 1000000000

# Use a specific EVM chain
dfx canister call evm_rpc request '(variant {Chain=0x1},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)' --wallet $(dfx identity get-wallet) --with-cycles 1000000000
```

## Reproducible Builds

The EVM RPC canister supports [reproducible builds](https://internetcomputer.org/docs/current/developer-docs/smart-contracts/test/reproducible-builds):

1. Ensure [Docker](https://www.docker.com/get-started/) is installed on your machine.
2. Run `scripts/docker-build` in your terminal. 
4. Run `sha256sum evm_rpc.wasm.gz` on the generated file to view the SHA-256 hash.

In order to verify the latest EVM RPC Wasm file, please make sure to download the corresponding version of the source code from the latest GitHub release.

## Contributing

Contributions are welcome! Please check out the [contributor guidelines](https://github.com/internet-computer-protocol/evm-rpc-canister/blob/main/.github/CONTRIBUTING.md) for more information.

Run the following commands to set up a local development environment:

```bash
# Clone the repository and install dependencies
git clone https://github.com/internet-computer-protocol/evm-rpc-canister
cd evm-rpc-canister
npm install

# Deploy to the local replica
dfx start --background
npm run generate
dfx deploy evm_rpc

# Alternatively, deploy and run test suite
dfx start --background
scripts/e2e
```

Regenerate language bindings with the `generate` [npm script](https://docs.npmjs.com/cli/v10/using-npm/scripts):

```bash
npm run generate
```

## Learn More

* [Candid interface](https://github.com/internet-computer-protocol/evm-rpc-canister/blob/main/candid/evm_rpc.did)

## Related Projects

* [`evm-rpc-canister-types`](https://crates.io/crates/evm-rpc-canister-types/3.0.0): Rust types for interacting with the EVM RPC canister.
* [`ic-evm-utils`](https://crates.io/crates/ic-evm-utils): A convenience crate for interacting with the EVM RPC Canister from canisters written in Rust.
* [chain-fusion-starter](https://github.com/letmejustputthishere/chain-fusion-starter): starter template leveraging chain fusion technology to build EVM coprocessors on the Internet Computer Protocol.
* [Bitcoin canister](https://github.com/dfinity/bitcoin-canister): interact with the Bitcoin blockchain from the Internet Computer.
* [ckETH](https://forum.dfinity.org/t/cketh-a-canister-issued-ether-twin-token-on-the-ic/22819): a canister-issued Ether twin token on the Internet Computer.
* [ICP 🔗 ETH](https://github.com/dfinity/icp-eth-starter): a full-stack starter project for calling Ethereum smart contracts from an IC dapp.
