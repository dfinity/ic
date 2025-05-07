#!/usr/bin/env python3
"""
Fetch Neuron Balance Example

This script demonstrates how to fetch neuron balances using the Internet Computer Rosetta API.
The script requires only the public key and neuron index, and automatically derives the neuron account ID.

Examples:
    # Get balance for a neuron (requires only public key and neuron index)
    python3 get_neuron_balance.py --node-address http://localhost:8081 --neuron-index 0 --public-key 022ac5b9bd21fa735e66bdd24c23e938daef472b95165a11bad4a43b2c95627ef3 --curve-type secp256k1

    # With verbose output
    python3 get_neuron_balance.py --node-address http://localhost:8081 --public-key 022ac5b9bd21fa735e66bdd24c23e938daef472b95165a11bad4a43b2c95627ef3 --curve-type secp256k1 --verbose

"""

import argparse
import json
import sys

from rosetta_client import RosettaClient


def format_balance(balance):
    """Format balance for display"""
    value = int(balance["balances"][0]["value"])
    decimals = balance["balances"][0]["currency"]["decimals"]
    symbol = balance["balances"][0]["currency"]["symbol"]
    return f"{value / 10**decimals} {symbol} ({value} e8s)"


def main():
    parser = argparse.ArgumentParser(description="Fetch neuron balances using Rosetta API")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--neuron-index", type=int, default=0, help="Neuron index")
    parser.add_argument("--public-key", type=str, required=True, help="Public key for neuron account (hex)")
    parser.add_argument(
        "--curve-type", type=str, required=True, help="Curve type for neuron public key (e.g., edwards25519, secp256k1)"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    # Prepare public key
    public_key = {"hex_bytes": args.public_key, "curve_type": args.curve_type}

    # Derive neuron account ID from public key
    neuron_account_id = client.get_account_identifier(
        public_key=public_key, neuron_index=args.neuron_index, verbose=args.verbose
    )

    print(f"\nDerived neuron account ID: {neuron_account_id}")
    print(f"Using neuron index: {args.neuron_index}")
    print(f"Using public key: {args.public_key}")
    print(f"Using curve type: {args.curve_type}")

    # Fetch neuron balance
    print("\nFetching neuron balance...")

    try:
        neuron_balance = client.get_neuron_balance(
            neuron_account_id, neuron_index=args.neuron_index, public_key=public_key, verbose=args.verbose
        )

        # Check if we got an error response
        if isinstance(neuron_balance, dict) and neuron_balance.get("status") == "error":
            if neuron_balance.get("error_type") == "neuron_not_found":
                print("No neuron found for the specified account and neuron index.")
                print(f"This may indicate that no neuron exists for this account at index {args.neuron_index}.")
                print("Try a different neuron index or verify that the account has staked neurons.")

                if args.verbose and "details" in neuron_balance:
                    print("\nError details:")
                    print(neuron_balance["details"])

                # Exit with a success code since this is an expected condition
                return 0
            else:
                # Some other error type
                print(f"Error: {neuron_balance.get('message', 'Unknown error')}")
                return 1

        # We have a valid neuron balance response
        print(f"Neuron Balance: {format_balance(neuron_balance)}")
        print(f"Block Height: {neuron_balance['block_identifier']['index']}")

        # If there's metadata in the response, display it
        if "metadata" in neuron_balance:
            print("\nNeuron Metadata:")
            print(json.dumps(neuron_balance["metadata"], indent=2))

        return 0

    except ValueError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
