#!/usr/bin/env python3
"""
Account Identifier Derivation Tool

This script derives both regular and neuron account identifiers from a public key.
- The regular account ID is used for the ICP ledger
- The neuron account ID is used for neurons in the NNS governance canister

Examples:
    # Derive account IDs (uses neuron index 0 by default)
    python3 get_account_id.py --node-address http://localhost:8081 --public-key ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d --curve-type edwards25519

    # Specify a different neuron index
    python3 get_account_id.py --node-address http://localhost:8081 --public-key ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d --curve-type edwards25519 --neuron-index 5

    # With verbose output
    python3 get_account_id.py --node-address http://localhost:8081 --public-key ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d --curve-type edwards25519 --verbose

"""

import argparse

from rosetta_client import RosettaClient


def main():
    parser = argparse.ArgumentParser(description="Derive account identifiers from public keys")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--public-key", type=str, required=True, help="Public key (hex)")
    parser.add_argument(
        "--curve-type", type=str, required=True, help="Curve type for public key (e.g., edwards25519, secp256k1)"
    )
    parser.add_argument("--neuron-index", type=int, default=0, help="Neuron index for neuron account ID (default: 0)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    # Prepare public key
    public_key = {"hex_bytes": args.public_key, "curve_type": args.curve_type}

    # Derive regular account ID
    regular_account_id = client.get_account_identifier(public_key=public_key, verbose=args.verbose)

    # Derive neuron account ID
    neuron_account_id = client.get_account_identifier(
        public_key=public_key, neuron_index=args.neuron_index, verbose=args.verbose
    )

    # Print results
    print("\nPublic Key Information:")
    print(f"  Public key: {args.public_key}")
    print(f"  Curve type: {args.curve_type}")

    print("\nDerived Account IDs:")
    print(f"  Regular account ID: {regular_account_id}")
    print(f"  Neuron account ID (index {args.neuron_index}): {neuron_account_id}")


if __name__ == "__main__":
    main()
