# Internet Computer Rosetta API Python Examples

This repository contains Python examples demonstrating how to interact with the Internet Computer through the Rosetta API.

## Table of Contents
- [Overview](#overview)
- [Setup](#setup)
- [Running the Examples](#running-the-examples)
- [Example Scripts](#example-scripts)
  - [Account Information](#account-information)
  - [Balance Queries](#balance-queries)
  - [Transferring ICP](#transferring-icp)
  - [Reading Blocks](#reading-blocks)
  - [Network Information](#network-information)
  - [NNS Governance](#nns-governance)
- [Testing All Examples](#testing-all-examples)
- [Understanding Response Formats](#understanding-response-formats)
- [Common Issues](#common-issues)

## Overview

The Rosetta API provides a standard interface for blockchain interactions. These examples demonstrate how to use the API for the Internet Computer Protocol (ICP), covering basic operations like checking balances, transferring tokens, and exploring governance proposals.

## Setup

Please refer to the [common setup instructions](../../README.md) for:
- Installing dependencies
- Generating keys (both Ed25519 and secp256k1 are supported for ICP operations)
- Accessing a Rosetta node

## Running the Examples

All examples require at minimum the `--node-address` parameter pointing to your Rosetta API endpoint. Most examples also support the `--verbose` flag for detailed output.

For any examples that use public keys:
- The `--public-key` parameter and `--curve-type` parameter MUST be provided together
- Neither parameter can be used without the other
- Valid curve types are `edwards25519` or `secp256k1`

This requirement applies to all scripts including `test_all.py`, `get_account_id.py`, and `get_neuron_balance.py`.

## Example Scripts

### Account Information

**Get Account Identifier**:
```sh
python get_account_id.py --node-address <NODE_ADDRESS> \
                        --public-key <YOUR_PUBLIC_KEY> \
                        --curve-type <CURVE_TYPE>
```

This script derives both regular and neuron account identifiers from a public key.

### Balance Queries

**Get Regular Account Balance**:
```sh
python get_account_balance.py --node-address <NODE_ADDRESS> \
                             --account-id <YOUR_ACCOUNT_ID>
```

**Get Neuron Balance**:

The following operation will fail if a public key that doesn't own a neuron is provided.
At the time of writing, the public key `022ac5b9bd21fa735e66bdd24c23e938daef472b95165a11bad4a43b2c95627ef3 (secp256k1)` has a neuron and can be used with this example.
If you want to create your own neurons, follow the [these instructions](https://support.dfinity.org/hc/en-us/articles/4404283954836-How-do-I-create-a-voting-neuron)

```sh
python get_neuron_balance.py --node-address <NODE_ADDRESS> \
                            --neuron-index 0 \
                            --public-key <YOUR_PUBLIC_KEY> \
                            --curve-type <CURVE_TYPE>
```

Note: The `--curve-type` parameter is mandatory when providing a public key.

### Transferring ICP

Transfer ICP tokens between accounts (requires a private key):

```sh
python transfer.py --node-address <NODE_ADDRESS> \
                  --private-key-path <YOUR_PRIVATE_KEY_PATH> \
                  --signature-type ecdsa \
                  --recipient-account-id <RECIPIENT_ACCOUNT_ID> \
                  --amount-e8s 1000000 \
                  --fee-e8s 10000
```

Note: 1 ICP = 100,000,000 e8s, so 1,000,000 e8s = 0.01 ICP

### Reading Blocks

Fetch and display recent blocks:

```sh
python read_blocks.py --node-address <NODE_ADDRESS>
```

This script fetches the most recent block and the 10 previous blocks, displaying their information.

### Network Information

Get comprehensive information about the Internet Computer network:

```sh
python get_network_info.py --node-address <NODE_ADDRESS>
```

This script retrieves available networks, network status (current block, genesis block, peers), and network options (supported features, operations, errors).

### NNS Governance

**List Known Neurons**:
```sh
python list_known_neurons.py --node-address <NODE_ADDRESS>
```

Lists all known neurons on the Network Nervous System (NNS) with their names and descriptions.

**List Pending Proposals**:
```sh
python list_pending_proposals.py --node-address <NODE_ADDRESS>
```

Lists all currently pending proposals on the NNS, showing titles, descriptions, proposers, and voting status.

**Get Specific Proposal Details**:
```sh
python get_proposal_info.py --node-address <NODE_ADDRESS> --proposal-id <PROPOSAL_ID>
```

Fetches detailed information about a specific proposal, including its status, voting results, proposer, and execution time.

**Get Minimum Dissolve Delay of a Neuron**:
```sh
python get_minimum_dissolve_delay.py --node-address <NODE_ADDRESS>
```

Returns the minimum dissolve delay of a neuron that still allows it to vote on NNS proposals.

## Testing All Examples

The `run_tests.sh` script provides a convenient way to test multiple examples at once. The script creates a clean virtual environment, installs dependencies, and then runs the appropriate tests based on the arguments you provide.

What's tested depends on which arguments you provide:

1. **Public Data Access** - Tests network information and block data:
```sh
# Tests only network and public blockchain data
./run_tests.sh --node-address <NODE_ADDRESS>
```

2. **Account Data Access** - Tests account operations and balances:
```sh
# Tests account operations requiring public key
./run_tests.sh --node-address <NODE_ADDRESS> \
              --public-key <YOUR_PUBLIC_KEY> \
              --curve-type <CURVE_TYPE>
```

3. **Transfer Functionality** - Tests all operations including ICP transfers:
```sh
# Tests everything including transfers (requires a funded account)
./run_tests.sh --node-address <NODE_ADDRESS> \
              --public-key <YOUR_PUBLIC_KEY> \
              --curve-type <CURVE_TYPE> \
              --funded-private-key-pem <YOUR_PRIVATE_KEY_PATH> \
              --recipient-account <RECIPIENT_ACCOUNT_ID>
```

Additional options:
- `--no-output`: Hide command outputs (show only success/failure)
- `--verbose`: Show verbose output including API requests and responses
- `--block-count`: Number of blocks to fetch when testing read_blocks (default: 5)

The script ensures a clean testing environment and makes it easy to run tests without worrying about dependency conflicts.

## Understanding Response Formats

Most scripts support a `--raw` flag to show the complete JSON response from the API:

```sh
python list_known_neurons.py --node-address <NODE_ADDRESS> --raw
```

For debugging, you can add the `--verbose` flag to see the API requests and responses:

```sh
python get_network_info.py --node-address <NODE_ADDRESS> --verbose
```

## Common Issues

1. **Error: Unable to connect to Rosetta node**
   - Ensure your Rosetta node is running
   - Check the URL format (e.g., <NODE_ADDRESS>)

2. **Error during transaction signing**
   - Verify that your private key file is in PEM format
   - Ensure you're using the correct signature type

3. **Error: Insufficient funds**
   - Check that your account has enough ICP for the transaction plus the fee

4. **Error: Unable to derive account identifier**
   - Make sure your public key is valid and in the correct format
   - For secp256k1, make sure the public key is in compressed format (33 bytes, starting with 02 or 03)
   - For ed25519, make sure the public key is 32 bytes
   - Ensure you've specified the correct curve type with `--curve-type`

5. **Error: Invalid public key**
   - Double-check that the extracted public key matches the required format for the specified curve type
   - For secp256k1, use: `openssl ec -in key.pem -pubout -conv_form compressed -outform DER | tail -c 33 | xxd -p -c 33`
   - For ed25519, use: `openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32` 