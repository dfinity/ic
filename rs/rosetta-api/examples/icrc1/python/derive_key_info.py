#!/usr/bin/env python3
"""
Derive Key Information Example

This script demonstrates how to derive public key and principal ID information
from a private key file for use with ICRC-1 ledgers on the Internet Computer.

The script:
1. Loads a private key file (in PEM format)
2. Derives the public key (in compressed hex format)
3. Derives a simplified principal ID from the public key
4. Displays the results

Examples:
    # Basic usage with a secp256k1 private key
    python3 derive_key_info.py --private-key-path ./my_private_key.pem

    # With verbose output
    python3 derive_key_info.py --private-key-path ./my_private_key.pem --verbose

Notes:
    This example provides a simplified derivation of principal IDs. The actual
    Internet Computer principal ID format uses a more complex algorithm including
    a CRC32 checksum. For production use, refer to the official documentation.

"""

import argparse
import json
import os
import sys

# Add the parent directory to the path to allow importing the common client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rosetta_client import RosettaClient


def parse_args():
    parser = argparse.ArgumentParser(description="Derive key information from a private key file")
    parser.add_argument("--private-key-path", type=str, required=True, help="Path to the private key file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"Deriving key information from: {args.private_key_path}")

    try:
        # Use the static method to derive key information
        key_info = RosettaClient.derive_key_info(private_key_path=args.private_key_path, verbose=args.verbose)

        # Display results
        if args.json:
            # The result is already JSON-safe
            print(json.dumps(key_info, indent=2))
        else:
            print("\nDerived Key Information:")
            print(f"Public Key (compressed): {key_info['public_key']['hex_bytes']}")
            print(f"Curve Type: {key_info['public_key']['curve_type']}")
            print(f"Derived Principal ID: {key_info['principal_id']}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
