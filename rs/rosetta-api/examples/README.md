# Internet Computer Rosetta API Examples

This directory contains examples for interacting with the Internet Computer through the Rosetta API.

## Available Examples

- [ICP Examples](icp/python/README.md) - Examples for interacting with the native ICP token
- [ICRC-1 Examples](icrc1/python/README.md) - Examples for interacting with ICRC-1 tokens (like ckBTC, CHAT, etc.)

## Common Setup

### Install Dependencies

Each example directory includes its own `requirements.txt` file. To install the dependencies:

```sh
pip install -r requirements.txt
```

### Access to a Rosetta Node

You'll need access to a Rosetta API endpoint, either:
- Local node running at the appropriate port
- Public endpoint (if available)

## Generating Keys

To sign transactions and derive account identifiers, you need key pairs. The Internet Computer supports different cryptographic curves. Both Ed25519 and secp256k1 key types can be used with both ICP and ICRC-1 tokens.

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

For common issues and troubleshooting, please refer to the specific README files for [ICP](icp/python/README.md#common-issues) or [ICRC-1](icrc1/python/README.md#common-issues) examples. 