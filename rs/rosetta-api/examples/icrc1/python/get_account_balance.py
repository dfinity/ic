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

    # Get aggregated balance across all subaccounts
    python3 get_account_balance.py --node-address http://localhost:8082 --canister-id <canister-id> --principal-id <principal-id> --aggregate

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
    parser.add_argument("--sub-account", type=str, help="Optional subaccount in hex format")
    parser.add_argument("--aggregate", action="store_true", help="Get aggregated balance across all subaccounts")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON response")

    args = parser.parse_args()

    # Initialize the Rosetta client
    client = RosettaClient(node_address=args.node_address, canister_id=args.canister_id, verbose=args.verbose)

    if args.verbose:
        print(f"Auto-discovered token: {client.token_info['symbol']} (decimals: {client.token_info['decimals']})")

    # Check for conflicting arguments
    if args.aggregate and args.sub_account:
        print("Error: Cannot specify both --aggregate and --sub-account flags")
        sys.exit(1)

    # Get the balance
    try:
        if args.aggregate:
            # Get aggregated balance across all subaccounts
            balance_response = client.get_aggregated_balance(principal=args.principal_id, verbose=args.verbose)
        else:
            # Handle optional subaccount for regular balance
            subaccount = args.sub_account if args.sub_account else None
            balance_response = client.get_balance(principal=args.principal_id, subaccount=subaccount, verbose=args.verbose)

        # Display the results
        if args.raw:
            print(json.dumps(balance_response, indent=2))
        else:
            # Get token information
            currency = balance_response["balances"][0]["currency"]
            symbol = currency["symbol"]
            decimals = currency["decimals"]
            raw_balance = int(balance_response["balances"][0]["value"])
            human_balance = raw_balance / (10**decimals)

            if args.aggregate:
                print("\nAggregated Account Balance:")
                print(f"  Principal: {args.principal_id}")
                print(f"  Scope: All subaccounts (aggregated)")
                print(f"  Token: {symbol} (decimals: {decimals})")
                print(f"  Total Balance: {human_balance} {symbol} ({raw_balance} raw units)")
                print(f"  Block Index: {balance_response['block_identifier']['index']}")
            else:
                print("\nAccount Balance:")
                print(f"  Principal: {args.principal_id}")
                if args.sub_account:
                    print(f"  Subaccount: {args.sub_account}")
                else:
                    print(f"  Subaccount: Default (None)")
                print(f"  Token: {symbol} (decimals: {decimals})")
                print(f"  Balance: {human_balance} {symbol} ({raw_balance} raw units)")
                print(f"  Block Index: {balance_response['block_identifier']['index']}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
