#!/usr/bin/env python3
"""
Fetch ICRC-1 Account Balance Example

This script demonstrates how to fetch account balances for ICRC-1 tokens
using the Internet Computer Rosetta API.

Examples:
    # Get balance for a specific account
    python3 get_account_balance.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id>

    # Get balance with subaccount
    python3 get_account_balance.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id> --sub-account <subaccount>

    # With verbose output
    python3 get_account_balance.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id> --verbose

    # With raw JSON output
    python3 get_account_balance.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id> --raw

"""

import argparse
import json
import os
import sys

# Add the parent directory to the path to allow importing the common client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rosetta_client import RosettaClient


def main():
    parser = argparse.ArgumentParser(description="Fetch balance for an ICRC-1 account")

    parser.add_argument(
        "--node-address", type=str, required=True, help="Rosetta API endpoint URL (e.g., http://localhost:8082)"
    )
    parser.add_argument("--canister-id", type=str, required=True, help="ICRC-1 canister ID")
    parser.add_argument("--principal-id", type=str, required=True, help="Principal ID to check balance for")
    parser.add_argument("--sub-account", type=str, help="Optional subaccount in hex format (default: none)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON response")

    args = parser.parse_args()

    # Initialize the Rosetta client
    client = RosettaClient(args.node_address, args.canister_id)

    # Get the balance
    try:
        balance_response = client.get_balance(
            principal=args.principal_id, subaccount=args.sub_account, verbose=args.verbose
        )

        # Display the results
        if args.raw:
            print(json.dumps(balance_response, indent=2))
        else:
            print("\nAccount Balance:")
            print(f"  Principal: {args.principal_id}")
            if args.sub_account:
                print(f"  Subaccount: {args.sub_account}")
            print(
                f"  Balance: {balance_response['balances'][0]['value']} {balance_response['balances'][0]['currency']['symbol']}"
            )
            print(f"  Block Index: {balance_response['block_identifier']['index']}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
