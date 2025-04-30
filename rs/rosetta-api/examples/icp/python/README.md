# Internet Computer Rosetta API Python Examples

This repository contains Python examples demonstrating how to interact with the Internet Computer through the Rosetta API.

## Table of Contents
- [Overview](#overview)
- [Setup](#setup)
- [Generating Keys](#generating-keys)
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

1. **Install dependencies**

```sh
pip install -r requirements.txt
```

2. **Access to a Rosetta node**

You'll need access to a Rosetta API endpoint, either:
- Local node running at http://localhost:8081
- Public endpoint (if available)

## Generating Keys

To sign transactions and derive account identifiers, you need a key pair. The Internet Computer supports different cryptographic curves:

### Ed25519 Keys

Generate an Ed25519 private key:

```sh
# Generate a private key in PEM format using ed25519 curve
$ openssl genpkey -algorithm ed25519 -out my_ed25519_key.pem

# View the private key details (optional)
$ openssl pkey -in my_ed25519_key.pem -text -noout
```

Extract the Ed25519 public key in the correct format:

```sh
# Extract compressed public key in hex format for Ed25519
$ openssl pkey -in my_ed25519_key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32
93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f
```

### secp256k1 Keys

Generate a secp256k1 private key:

```sh
# Generate a private key in PEM format using secp256k1 curve
$ openssl ecparam -name secp256k1 -genkey -noout -out my_secp256k1_key.pem

# View the private key details and confirm the curve type
$ openssl ec -in my_secp256k1_key.pem -text -noout
$ openssl ec -in my_secp256k1_key.pem -text -noout | grep 'ASN1 OID'
ASN1 OID: secp256k1
```

Extract the secp256k1 public key in the correct format:

```sh
# Extract compressed public key in hex format for secp256k1
$ openssl ec -in my_secp256k1_key.pem -pubout -conv_form compressed -outform DER | tail -c 33 | xxd -p -c 33
03e4be477eb605d5d0738f643b2f6d8ffea8685855bc60d03f58244a15130a0ef8
```

Note the important differences:
- Ed25519 public keys are 32 bytes
- secp256k1 compressed public keys are 33 bytes, with the first byte being either `02` or `03`

## Running the Examples

All examples require at minimum the `--node-address` parameter pointing to your Rosetta API endpoint. Most examples also support the `--verbose` flag for detailed output.

For any examples that require a public key, you **must** specify the curve type using the `--curve-type` parameter (either `edwards25519` or `secp256k1`).

## Example Scripts

### Account Information

**Get Account Identifier**:
```sh
# Using Ed25519 public key
python get_account_id.py --node-address http://localhost:8081 \
                        --public-key 93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f \
                        --curve-type edwards25519

# Using secp256k1
python get_account_id.py --node-address http://localhost:8081 \
                        --public-key 03e4be477eb605d5d0738f643b2f6d8ffea8685855bc60d03f58244a15130a0ef8 \
                        --curve-type secp256k1
```

This script derives both regular and neuron account identifiers from a public key.

### Balance Queries

**Get Regular Account Balance**:
```sh
python get_account_balance.py --node-address http://localhost:8081 \
                             --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4
```

**Get Neuron Balance**:
```sh
# Using Ed25519 public key
python get_neuron_balance.py --node-address http://localhost:8081 \
                            --neuron-index 0 \
                            --public-key 93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f \
                            --curve-type edwards25519

# Using secp256k1 public key
python get_neuron_balance.py --node-address http://localhost:8081 \
                            --neuron-index 0 \
                            --public-key 03e4be477eb605d5d0738f643b2f6d8ffea8685855bc60d03f58244a15130a0ef8 \
                            --curve-type secp256k1
```

Note: The `--curve-type` parameter is mandatory when providing a public key.

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

This script fetches the most recent block and the 10 previous blocks, displaying their information.

### Network Information

Get comprehensive information about the Internet Computer network:

```sh
python get_network_info.py --node-address http://localhost:8081
```

This script retrieves available networks, network status (current block, genesis block, peers), and network options (supported features, operations, errors).

### NNS Governance

**List Known Neurons**:
```sh
python list_known_neurons.py --node-address http://localhost:8081
```

Lists all known neurons on the Network Nervous System (NNS) with their names and descriptions.

**List Pending Proposals**:
```sh
python list_pending_proposals.py --node-address http://localhost:8081
```

Lists all currently pending proposals on the NNS, showing titles, descriptions, proposers, and voting status.

**Get Specific Proposal Details**:
```sh
python get_proposal_info.py --node-address http://localhost:8081 --proposal-id 123456
```

Fetches detailed information about a specific proposal, including its status, voting results, proposer, and execution time.

## Testing All Examples

### Using the Python Test Script

The `test_all.py` script allows you to test all the examples at once:

```sh
# Basic test of all non-destructive examples (curve type is required)
python test_all.py --node-address http://localhost:8081 --curve-type edwards25519
```

For more comprehensive testing including transfers (which require a funded account):

```sh
python test_all.py --node-address http://localhost:8081 \
                  --curve-type edwards25519 \
                  --funded_private_key_pem ./my_private_key.pem \
                  --recipient_account 47e0ae0de8af04a961c4b3225cd77b9652777286ce142c2a07fab98da5263100
```

To test neuron balance functionality (requires a public key associated with neurons):

```sh
python test_all.py --node-address http://localhost:8081 \
                  --curve-type edwards25519 \
                  --public_key_with_neurons 93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f
```

### Using the Automated Test Script

For convenience, a bash script `run_tests.sh` is provided that:
1. Checks if virtualenv is installed (and attempts to install it if not)
2. Creates a new virtual environment 
3. Installs all dependencies from requirements.txt
4. Runs the test_all.py script with any arguments you provide
5. Cleans up the virtual environment afterward

To use it:

```sh
# Run basic tests (a default curve-type of edwards25519 will be used if not specified)
./run_tests.sh --node-address http://localhost:8081

# Run with explicit curve type
./run_tests.sh --node-address http://localhost:8081 --curve-type edwards25519

# Run with additional test options
./run_tests.sh --node-address http://localhost:8081 \
              --curve-type edwards25519 \
              --funded_private_key_pem ./my_private_key.pem \
              --recipient_account 47e0ae0de8af04a961c4b3225cd77b9652777286ce142c2a07fab98da5263100 \
              --public_key_with_neurons 93f14fad36957237baab3b7ce8890c766b44c7071bda09830592379f2a2d418f
```

This script ensures a clean testing environment and makes it easy to run tests without worrying about dependency conflicts.

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
   - Make sure your public key is valid and in the correct format
   - For secp256k1, make sure the public key is in compressed format (33 bytes, starting with 02 or 03)
   - For ed25519, make sure the public key is 32 bytes
   - Ensure you've specified the correct curve type with `--curve-type`

5. **Error: Invalid public key**
   - Double-check that the extracted public key matches the required format for the specified curve type
   - For secp256k1, use: `openssl ec -in key.pem -pubout -conv_form compressed -outform DER | tail -c 33 | xxd -p -c 33`
   - For ed25519, use: `openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32` 