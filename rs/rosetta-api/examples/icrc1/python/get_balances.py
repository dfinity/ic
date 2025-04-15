#!/usr/bin/env python3
"""
Fetch ICRC-1 Account Balances Example

This script demonstrates how to fetch account balances for ICRC-1 tokens
using the Internet Computer Rosetta API.

Examples:
    # Get balance for a specific account
    python3 get_balances.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai

    # Get balance with subaccount
    python3 get_balances.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai --sub-account 0000000000000000000000000000000000000000000000000000000000000000

    # With verbose output
    python3 get_balances.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai --verbose
"""

from rosetta_client import RosettaClient
import argparse
import json

def format_balance(balance):
    """Format balance for display"""
    value = int(balance["balances"][0]["value"])
    decimals = balance["balances"][0]["currency"]["decimals"]
    symbol = balance["balances"][0]["currency"]["symbol"]
    return f"{value / 10**decimals} {symbol} ({value} raw)"

def main():
    parser = argparse.ArgumentParser(description='Fetch ICRC-1 account balances using Rosetta API')
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--canister-id", type=str, required=True, help="Canister ID of the ICRC-1 ledger")
    parser.add_argument("--principal-id", type=str, required=True, help="Principal identifier to check balance for")
    parser.add_argument("--sub-account", type=str, help="Subaccount in hex (default is all zeros)")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    client = RosettaClient(args.node_address, args.canister_id)
    
    print(f"\nFetching balance for principal: {args.principal_id}")
    if args.sub_account:
        print(f"With subaccount: {args.sub_account}")
        
    balance = client.get_balance(args.principal_id, args.sub_account, verbose=args.verbose)
    
    if args.raw:
        print("\nRaw Response:")
        print(json.dumps(balance, indent=2))
    else:
        print(f"Account Balance: {format_balance(balance)}")
        print(f"Block Height: {balance['block_identifier']['index']}")
        print(f"Block Hash: {balance['block_identifier']['hash']}")

if __name__ == "__main__":
    main() 