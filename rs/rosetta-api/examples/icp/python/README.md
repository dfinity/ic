# Internet Computer Rosetta API Python Examples

This repository contains Python examples demonstrating how to interact with the Internet Computer through the Rosetta API.

## Table of Contents
- [Overview](#overview)
- [Setup](#setup)
- [Generating ECDSA Keys](#generating-ecdsa-keys)
- [Running the Examples](#running-the-examples)
- [Example Scripts](#example-scripts)
  - [Account and Neuron Balances](#account-and-neuron-balances)
  - [Transferring ICP](#transferring-icp)
  - [Reading Blocks](#reading-blocks)
  - [Searching Transactions](#searching-transactions)
  - [Network Information](#network-information)
  - [NNS Governance](#nns-governance)
- [Understanding Response Formats](#understanding-response-formats)

## Overview

The Rosetta API provides a standard interface for blockchain interactions. These examples demonstrate how to use the API for the Internet Computer Protocol (ICP), covering basic operations like checking balances, transferring tokens, and exploring governance proposals.

## Setup

1. **Install dependencies**

```sh
pip install -r requirements.txt
```

2. **Access to a Rosetta node**

You'll need access to a Rosetta API endpoint, either:
- Local node running at http://localhost:8081
- Public endpoint (if available)

## Generating ECDSA Keys

To sign transactions (required for transfers), you need an ECDSA private key. Here's how to generate one:

```sh
# Generate a private key in PEM format
openssl ecparam -name secp256k1 -genkey -noout -out my_private_key.pem

# View the private key (optional)
openssl ec -in my_private_key.pem -text -noout

# Generate corresponding public key
openssl ec -in my_private_key.pem -pubout -out my_public_key.pem
```

## Running the Examples

All examples require at minimum the `--node-address` parameter pointing to your Rosetta API endpoint.

## Example Scripts

### Account and Neuron Balances

**Get Account Balance**:
```sh
python get_balances.py --node-address http://localhost:8081 \
                       --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4
```

**Get Neuron Balance**:
```sh
python get_balances.py --node-address http://localhost:8081 \
                       --neuron-account-id a4ac33c6a25a102756e3aac64fe9d3267dbef25392d031cfb3d2185dba93b4c4 \
                       --neuron-index 0
```

### Transferring ICP

Transfer ICP tokens between accounts (requires a private key):

```sh
python transfer.py --node-address http://localhost:8081 \
                  --private-key-path ./my_private_key.pem \
                  --signature-type ecdsa \
                  --recipient-account-id 47e0ae0de8af04a961c4b3225cd77b9652777286ce142c2a07fab98da5263100 \
                  --amount-e8s 1000000 \
                  --fee-e8s 10000
```

Note: 1 ICP = 100,000,000 e8s, so 1,000,000 e8s = 0.01 ICP

### Reading Blocks

Fetch and display recent blocks:

```sh
python read_blocks.py --node-address http://localhost:8081
```

### Searching Transactions

**Get a specific transaction**:
```sh
python search_transactions.py --node-address http://localhost:8081 \
                             --block-index 9840566 \
                             --transaction-hash 93a19bfa37db0200cec77281cd8a0602a4375a7367338e7c6973f93a42e6eb5e
```

**Search transactions for an account**:
```sh
python search_transactions.py --node-address http://localhost:8081 \
                             --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4
```

**View transactions from the latest block**:
```sh
python search_transactions.py --node-address http://localhost:8081
```

### Network Information

Get information about the Internet Computer network:

```sh
python get_network_info.py --node-address http://localhost:8081
```

### NNS Governance

**List Known Neurons**:
```sh
python list_known_neurons.py --node-address http://localhost:8081
```

**List Pending Proposals**:
```sh
python list_pending_proposals.py --node-address http://localhost:8081
```

**Get Specific Proposal Details**:
```sh
python get_proposal_info.py --node-address http://localhost:8081 --proposal-id 123456
```

## Understanding Response Formats

Most scripts support a `--raw` flag to show the complete JSON response from the API:

```sh
python list_known_neurons.py --node-address http://localhost:8081 --raw
```

For debugging, you can add the `--verbose` flag to see the API requests and responses:

```sh
python get_network_info.py --node-address http://localhost:8081 --verbose
```

## Common Issues

1. **Error: Unable to connect to Rosetta node**
   - Ensure your Rosetta node is running
   - Check the URL format (e.g., http://localhost:8081)

2. **Error during transaction signing**
   - Verify that your private key file is in PEM format
   - Ensure you're using the correct signature type

3. **Error: Insufficient funds**
   - Check that your account has enough ICP for the transaction plus the fee

4. **Error: Unable to derive account identifier**
   - Make sure your private key is valid and in the correct format 