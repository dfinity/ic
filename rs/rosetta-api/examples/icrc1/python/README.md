# ICRC-1 Rosetta API Python Client

This Python client library provides tools for interacting with ICRC-1 tokens on the Internet Computer blockchain through the Rosetta API. It offers functionality for account balance queries, token transfers, block data retrieval, and more.

## Features

- **Automatic Token Discovery**: The client automatically discovers token information (symbol and decimals) using multiple methods:
  1. Network options API
  2. Block history scanning
  3. Fallback to defaults (ICRC1, 8 decimals)

- **Account Management**: Create and manage accounts with principal IDs and optional subaccounts

- **Balance Queries**: Fetch token balances for any account

- **Transaction Processing**: Transfer tokens between accounts with appropriate fee handling

- **Block Data Retrieval**: Read block data, search for transactions, and examine the chain state

## Code Design

The client is designed with simplicity and maintainability in mind:

- **Helper Methods**: Complex functionality is broken down into smaller, focused helper methods
- **Clean Structure**: Early returns are used instead of deep nesting to improve readability
- **Clear Abstractions**: Each component has a single responsibility
- **Robust Testing**: Unit tests with mocking validate the functionality without network calls
- **Consistent Patterns**: Standardized error handling and response formatting throughout

This approach makes the code easier to maintain, extend, and understand.

## Usage Examples

### Basic Client Initialization

```python
from rosetta_client import RosettaClient

# Initialize the client
client = RosettaClient(
    node_address="http://localhost:8080",
    canister_id="3jkp5-oyaaa-aaaaj-azwqa-cai"
)

# The client automatically discovers token information
print(f"Token: {client.token_info['symbol']} (decimals: {client.token_info['decimals']})")
```

### Checking Account Balance

```python
# Get account balance (with auto-discovered token info)
balance = client.get_balance(principal="abc123...")
print(f"Balance: {int(balance['balances'][0]['value']) / 10**balance['balances'][0]['currency']['decimals']} {balance['balances'][0]['currency']['symbol']}")

# Get aggregated balance across all subaccounts
aggregated_balance = client.get_aggregated_balance(principal="abc123...")
print(f"Total Balance (All Subaccounts): {int(aggregated_balance['balances'][0]['value']) / 10**aggregated_balance['balances'][0]['currency']['decimals']} {aggregated_balance['balances'][0]['currency']['symbol']}")
```

### Making a Transfer

```python
# Setup with private key (for signing transactions)
client.setup_keys(private_key_path="./my_key.pem")

# Transfer tokens
result = client.transfer(
    from_principal="sender-principal",
    to_principal="recipient-principal",
    amount=1000000,  # Raw token amount
    fee=10000,       # Transaction fee
    private_key_path="./my_key.pem"
)

print(f"Transaction hash: {result['transaction_identifier']['hash']}")
```

## Available Tools

- **get_token_info.py**: Shows token information discovery process
- **get_account_balance.py**: Displays account balance with human-readable formatting
- **transfer.py**: Transfers tokens between accounts
- **test_token_info.py**: Demonstrates and tests token info discovery process

## Token Information Discovery

The client implements multiple ways to discover token information:

1. **Network Options**: First tries to get token info from the `/network/options` endpoint
2. **Block History**: If network options don't contain token info, examines recent blocks (transactions)
3. **Default Fallback**: Uses ICRC1 symbol and 8 decimals if no other information is available
4. **Manual Override**: Allows explicit setting via `client.token_override = {"symbol": "...", "decimals": ...}`

This multi-layered approach ensures the client always has access to token information for proper formatting and display of token amounts.

# Internet Computer ICRC-1 Rosetta API Python Examples

This repository contains Python examples demonstrating how to interact with ICRC-1 tokens on the Internet Computer through the Rosetta API.

## Table of Contents
- [Overview](#overview)
- [Setup](#setup)
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

Please refer to the [common setup instructions](../../README.md) for:
- Installing dependencies
- Generating keys (both Ed25519 and secp256k1 are supported for ICRC-1 tokens)
- Accessing a Rosetta node

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

**Get Aggregated Balance (All Subaccounts)**:
```sh
python3 get_account_balance.py --node-address http://localhost:8082 \
                       --canister-id <canister-id> \
                       --principal-id <principal-id> \
                       --aggregate
```

The aggregated balance feature returns the sum of balances across all subaccounts of a principal, which is useful for:
- Getting the total balance of a user across all their subaccounts
- Portfolio management and reporting  
- Simplified balance checking without needing to query each subaccount individually

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