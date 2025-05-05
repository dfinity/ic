#!/usr/bin/env python3
"""
Fetch Account Balance Example

This script demonstrates how to fetch regular account balances
using the Internet Computer Rosetta API.

Examples:
    # Get balance for a specific account
    python3 get_account_balance.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4

    # With verbose output
    python3 get_account_balance.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --verbose

"""

import argparse

from rosetta_client import RosettaClient


def format_balance(balance):
    """Format balance for display"""
    value = int(balance["balances"][0]["value"])
    decimals = balance["balances"][0]["currency"]["decimals"]
    symbol = balance["balances"][0]["currency"]["symbol"]
    return f"{value / 10**decimals} {symbol} ({value} e8s)"


def main():
    parser = argparse.ArgumentParser(description="Fetch account balances using Rosetta API")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument(
        "--account-id",
        type=str,
        required=True,
        help="Account identifier to check balance for",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    # Fetch regular account balance
    print(f"\nFetching balance for account: {args.account_id}")
    balance = client.get_balance(args.account_id, verbose=args.verbose)
    print(f"Account Balance: {format_balance(balance)}")
    print(f"Block Height: {balance['block_identifier']['index']}")


if __name__ == "__main__":
    main()
