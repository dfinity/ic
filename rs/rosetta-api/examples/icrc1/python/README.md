# Internet Computer ICRC-1 Rosetta API Python Examples

This repository contains Python examples demonstrating how to interact with ICRC-1 tokens on the Internet Computer through the Rosetta API.

## Table of Contents
- [Overview](#overview)
- [Setup](#setup)
- [Generating ECDSA Keys](#generating-ecdsa-keys)
- [Running the Examples](#running-the-examples)
- [Example Scripts](#example-scripts)
  - [Account Balances](#account-balances)
  - [Reading Blocks](#reading-blocks)
  - [Searching Transactions](#searching-transactions)
  - [Network Information](#network-information)
  - [Transferring Tokens](#transferring-tokens)
- [Understanding Response Formats](#understanding-response-formats)

## Overview

The ICRC Rosetta API provides a standardized interface for blockchain interactions with ICRC-1 tokens (like ckBTC, CHAT, and other tokens) on the Internet Computer. These examples demonstrate how to use the API for basic operations like checking balances, reading blocks, and exploring transactions.

## Setup

1. **Install dependencies**

```sh
pip install -r requirements.txt
```

2. **Access to a Rosetta node**

You'll need access to an ICRC Rosetta API endpoint, either:
- Local node running at http://localhost:8082
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

All examples require at minimum the `--node-address` and `--canister-id` parameters. The `--node-address` points to your ICRC Rosetta API endpoint, and the `--canister-id` identifies the specific ICRC-1 ledger canister (e.g., ckBTC, CHAT) you want to interact with.

## Example Scripts

### Account Balances

**Get Account Balance**:
```sh
python get_balances.py --node-address http://localhost:8082 \
                       --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                       --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai \
                       --sub-account 0000000000000000000000000000000000000000000000000000000000000000
```

### Reading Blocks

Fetch and display recent blocks:

```sh
python read_blocks.py --node-address http://localhost:8082 \
                      --canister-id mxzaz-hqaaa-aaaar-qaada-cai
```

**Get a specific block**:
```sh
python read_blocks.py --node-address http://localhost:8082 \
                      --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                      --block-index 1357691
```

### Searching Transactions

**Get a specific transaction**:
```sh
python search_transactions.py --node-address http://localhost:8082 \
                             --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                             --block-index 1357691 \
                             --transaction-hash 700481a99b9a10cf4c4d037141ae5f1472fefe1f5be6b43d02577e398da4bdfe
```

**Search transactions for a principal**:
```sh
python search_transactions.py --node-address http://localhost:8082 \
                             --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                             --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai
```

**View transactions from the latest block**:
```sh
python search_transactions.py --node-address http://localhost:8082 \
                             --canister-id mxzaz-hqaaa-aaaar-qaada-cai
```

### Network Information

Get information about the ICRC-1 ledger network:

```sh
python get_network_info.py --node-address http://localhost:8082 \
                          --canister-id mxzaz-hqaaa-aaaar-qaada-cai
```

### Transferring Tokens

Transfer ICRC-1 tokens between accounts (requires a private key):

```sh
python transfer.py --node-address http://localhost:8082 \
                   --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                   --private-key-path ./my_private_key.pem \
                   --signature-type ecdsa \
                   --from-principal lrf2i-zba54-pygwt-tbi75-zvlz4-7gfhh-ylcrq-2zh73-6brgn-45jy5-cae \
                   --to-principal xmiu5-jqaaa-aaaag-qbz7q-cai \
                   --amount 100000 \
                   --fee 100000
```

## Understanding Response Formats

Most scripts support a `--raw` flag to show the complete JSON response from the API:

```sh
python read_blocks.py --node-address http://localhost:8082 \
                     --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                     --raw
```

For debugging, you can add the `--verbose` flag to see the API requests and responses:

```sh
python get_network_info.py --node-address http://localhost:8082 \
                          --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
                          --verbose
```

## Common Issues

1. **Error: Unable to connect to Rosetta node**
   - Ensure your ICRC Rosetta node is running
   - Check the URL format (e.g., http://localhost:8082)

2. **Error during transaction signing**
   - Verify that your private key file is in PEM format
   - Ensure you're using the correct signature type

3. **Error: Insufficient funds**
   - Check that your account has enough tokens for the transaction plus the fee

4. **Error: Unable to derive account identifier**
   - Make sure your private key is valid and in the correct format 