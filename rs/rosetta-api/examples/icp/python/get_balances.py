#!/usr/bin/env python3
"""
Fetch Account Balances Example

This script demonstrates how to fetch account balances and neuron balances
using the Internet Computer Rosetta API.

Examples:
    # Get balance for a specific account
    python3 get_balances.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4

    # Get balance for a neuron account
    python3 get_balances.py --node-address http://localhost:8081 --neuron-account-id a4ac33c6a25a102756e3aac64fe9d3267dbef25392d031cfb3d2185dba93b4c4 --neuron-index 0

    # With public key information
    python3 get_balances.py --node-address http://localhost:8081 --neuron-account-id a4ac33c6a25a102756e3aac64fe9d3267dbef25392d031cfb3d2185dba93b4c4 --public-key ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d --curve-type edwards25519

    # With verbose output
    python3 get_balances.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --verbose
"""

from rosetta_client import RosettaClient
import argparse
import json

def format_balance(balance):
    """Format balance for display"""
    value = int(balance["balances"][0]["value"])
    decimals = balance["balances"][0]["currency"]["decimals"]
    symbol = balance["balances"][0]["currency"]["symbol"]
    return f"{value / 10**decimals} {symbol} ({value} e8s)"

def main():
    parser = argparse.ArgumentParser(description='Fetch account and neuron balances using Rosetta API')
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--account-id", type=str, help="Account identifier to check balance for")
    parser.add_argument("--neuron-account-id", type=str, help="Neuron account identifier")
    parser.add_argument("--neuron-index", type=int, default=0, help="Neuron index")
    parser.add_argument("--public-key", type=str, help="Public key for neuron account (hex)")
    parser.add_argument("--curve-type", type=str, default="edwards25519", help="Curve type for neuron public key")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    client = RosettaClient(args.node_address)
    
    # Fetch regular account balance
    if args.account_id:
        print(f"\nFetching balance for account: {args.account_id}")
        balance = client.get_balance(args.account_id, verbose=args.verbose)
        print(f"Account Balance: {format_balance(balance)}")
        print(f"Block Height: {balance['block_identifier']['index']}")
    else:
        print("\nNo account ID provided, skipping account balance check")
    
    # Fetch neuron balance
    if args.neuron_account_id:
        print(f"\nFetching neuron balance for account: {args.neuron_account_id}")
        
        # Prepare public key if provided
        public_key = None
        if args.public_key:
            public_key = {
                "hex_bytes": args.public_key,
                "curve_type": args.curve_type
            }
        
        neuron_balance = client.get_neuron_balance(
            args.neuron_account_id, 
            neuron_index=args.neuron_index,
            public_key=public_key,
            verbose=args.verbose
        )
        
        print(f"Neuron Balance: {format_balance(neuron_balance)}")
        print(f"Block Height: {neuron_balance['block_identifier']['index']}")
        
        # If there's metadata in the response, display it
        if 'metadata' in neuron_balance:
            print("\nNeuron Metadata:")
            print(json.dumps(neuron_balance['metadata'], indent=2))
    else:
        print("\nNo neuron account ID provided, skipping neuron balance check")

if __name__ == "__main__":
    main() 