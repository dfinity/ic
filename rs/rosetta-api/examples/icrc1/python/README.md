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
- [Testing All Examples](#testing-all-examples)
  - [Using the Python Test Script](#using-the-python-test-script)
  - [Using the Automated Test Script](#using-the-automated-test-script)
- [Understanding Response Formats](#understanding-response-formats)
- [Common Issues](#common-issues)

## Overview

The ICRC Rosetta API provides a standardized interface for blockchain interactions with ICRC-1 tokens (like ckBTC, CHAT, and other tokens) on the Internet Computer. These examples demonstrate how to use the API for basic operations like checking balances, reading blocks, and exploring transactions.

## Setup

1. **Install dependencies**

```sh
pip3 install -r requirements.txt
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

All examples require at minimum the `--node-address` and `--canister-id` parameters. The `--node-address` points to your ICRC Rosetta API endpoint, and the `--canister-id` identifies the specific ICRC-1 ledger canister (e.g., ckBTC, CHAT) you want to interact with. Most examples also require a principal ID.

**Important:** No default values are provided for canister IDs or principal IDs. These must be explicitly provided in all commands.

## Example Scripts

### Account Balances

**Get Account Balance**:
```sh
python3 get_account_balance.py --node-address http://localhost:8082 \
                       --canister-id <canister-id> \
                       --principal-id <principal-id> \
                       --sub-account <optional-subaccount>
```

### Key Information

**Derive Public Key and Principal ID**:
```sh
python3 derive_key_info.py --private-key-path ./my_private_key.pem
```

This script demonstrates how to extract public key information and derive a principal ID from a private key file.

**With verbose output**:
```sh
python3 derive_key_info.py --private-key-path ./my_private_key.pem --verbose
```

**With JSON output**:
```sh
python3 derive_key_info.py --private-key-path ./my_private_key.pem --json
```

Note: This script provides a simplified approach to principal ID derivation. For production use, consider using the official Internet Computer SDK libraries.

### Reading Blocks

Fetch and display recent blocks:

```sh
python3 read_blocks.py --node-address http://localhost:8082 \
                      --canister-id <canister-id>
```

**Get a specific block**:
```sh
python3 read_blocks.py --node-address http://localhost:8082 \
                      --canister-id <canister-id> \
                      --block-index <block-number>
```


### Network Information

Get information about the ICRC-1 ledger network:

```sh
python3 get_network_info.py --node-address http://localhost:8082 \
                          --canister-id <canister-id>
```

### Transferring Tokens

Transfer ICRC-1 tokens between accounts (requires a private key):

```sh
python3 transfer.py --node-address http://localhost:8082 \
                   --canister-id <canister-id> \
                   --private-key-path ./my_private_key.pem \
                   --signature-type ecdsa \
                   --to-principal <to-principal-id> \
                   --amount <amount> \
                   --fee <fee>
```

When using this command, the sender's principal ID will be automatically derived from the private key.

## Testing All Examples

### Using the Python Test Script

The `test_all.py` script allows you to test all the examples at once:

```sh
# Basic test of all non-destructive examples (requires principal ID)
python3 test_all.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id>
```

For more comprehensive testing including transfers (which require a funded account):

```sh
python3 test_all.py --node-address http://localhost:8082 \
                  --canister-id <canister-id> \
                  --principal-id <principal-id> \
                  --private-key-path ./my_private_key.pem \
                  --to-principal <to-principal-id> \
                  --amount <amount> \
                  --fee <fee>
```

The default values are 100 for amount and 10 for fee if not specified.

### Using the Automated Test Script

For convenience, a bash script `run_tests.sh` is provided that:
1. Checks if virtualenv is installed (and attempts to install it if not)
2. Creates a new virtual environment 
3. Installs all dependencies from requirements.txt
4. Runs the test_all.py script with any arguments you provide
5. Cleans up the virtual environment afterward

To use it:

```sh
# Run tests with all required parameters
./run_tests.sh --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id>

# Run with additional test options including transfer
./run_tests.sh --node-address http://localhost:8082 \
              --canister-id <canister-id> \
              --principal-id <principal-id> \
              --private-key-path ./my_private_key.pem \
              --to-principal <to-principal-id> \
              --amount 1000 \
              --fee 10
```

This script ensures a clean testing environment and makes it easy to run tests without worrying about dependency conflicts.

## Understanding Response Formats

Most scripts support a `--raw` flag to show the complete JSON response from the API:

```sh
python3 read_blocks.py --node-address http://localhost:8082 \
                     --canister-id <canister-id> \
                     --raw
```

For debugging, you can add the `--verbose` flag to see the API requests and responses:

```sh
python3 get_network_info.py --node-address http://localhost:8082 \
                          --canister-id <canister-id> \
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