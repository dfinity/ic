#!/usr/bin/env python3
"""
Get Token Information Example

This script demonstrates how to retrieve token information (symbol and decimals)
from an ICRC-1 ledger using various methods available in the Rosetta API client.

Examples:
    python3 get_token_info.py --node-address http://localhost:8080 --canister-id <canister-id>

    # With verbose output to see all the attempts
    python3 get_token_info.py --node-address http://localhost:8080 --canister-id <canister-id> --verbose

    # Additional optionally check balance of a principal
    python3 get_token_info.py --node-address http://localhost:8080 --canister-id <canister-id> --principal-id <principal-id>

"""

import argparse
import json
import os
import sys

# Add the parent directory to the path to allow importing the client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rosetta_client import RosettaClient


def get_token_info_from_options(client, verbose):
    """Get token information from /network/options endpoint"""
    if verbose:
        print("\nAttempting to get token info from network options...")

    try:
        options = client.get_options(verbose=verbose)

        # Early return if no options or currencies
        if "allow" not in options or "currencies" not in options["allow"] or not options["allow"]["currencies"]:
            if verbose:
                print("❌ No token info found in network options")
            return None

        # Get the first currency
        currency = options["allow"]["currencies"][0]
        token_info = {"symbol": currency.get("symbol", "Unknown"), "decimals": currency.get("decimals", 8)}

        if verbose:
            print(f"✅ Found token info from network options: {token_info}")

        return token_info

    except Exception as e:
        if verbose:
            print(f"❌ Failed to get token info from network options: {e}")

    return None


def get_token_info_from_balance(client, principal_id, verbose):
    """Get token information from account balance query"""
    # Early return if no principal provided
    if not principal_id:
        if verbose:
            print("❌ Cannot check balance without a principal ID")
        return None

    if verbose:
        print(f"\nAttempting to get token info from balance of {principal_id}...")

    try:
        balance_info = client.get_balance(principal=principal_id, subaccount=None, verbose=verbose)

        # Check if we have balances with currency info
        if "balances" not in balance_info or not balance_info["balances"]:
            if verbose:
                print("❌ No balance information returned")
            return None

        currency = balance_info["balances"][0].get("currency", {})

        # Create token info object
        token_info = {"symbol": currency.get("symbol", "Unknown"), "decimals": currency.get("decimals", 8)}

        if verbose:
            print(f"✅ Found token info from balance query: {token_info}")

        return token_info

    except Exception as e:
        if verbose:
            print(f"❌ Failed to get token info from balance query: {e}")

    return None


def main():
    parser = argparse.ArgumentParser(description="Get token information from an ICRC-1 ledger")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta API endpoint URL")
    parser.add_argument("--canister-id", type=str, required=True, help="ICRC-1 canister ID")
    parser.add_argument("--principal-id", type=str, help="Optional principal ID to check balance")
    parser.add_argument("--num-blocks", type=int, required=True, help="Number of blocks to check")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON")

    args = parser.parse_args()

    # Initialize the Rosetta client
    client = RosettaClient(node_address=args.node_address, canister_id=args.canister_id, verbose=args.verbose)

    if args.verbose:
        print(f"Attempting to discover token information for canister: {args.canister_id}")

    # Create dictionary to store token info from different methods
    results = {
        "network_options": get_token_info_from_options(client, verbose=args.verbose),
        "recent_blocks": client.get_token_info_from_blocks(num_blocks=args.num_blocks, verbose=args.verbose),
    }

    # Add account balance method if principal provided
    if args.principal_id:
        results["account_balance"] = get_token_info_from_balance(
            client, principal_id=args.principal_id, verbose=args.verbose
        )

    # Determine best token info (using priority order)
    token_info = determine_best_token_info(results)

    # Output the results
    output_results(args.raw, results, token_info)


def determine_best_token_info(results):
    """Determine the best token info available based on priority"""
    # Priority: 1) network options, 2) account balance, 3) recent blocks
    if results["network_options"]:
        return {"info": results["network_options"], "source": "network options"}
    elif "account_balance" in results and results["account_balance"]:
        return {"info": results["account_balance"], "source": "account balance"}
    elif results["recent_blocks"]:
        return {"info": results["recent_blocks"], "source": "recent blocks"}
    else:
        return None


def output_results(raw, results, token_info):
    """Output the token information results"""
    if raw:
        print(json.dumps(results, indent=2))
    else:
        print("\n=== Token Information Discovery Results ===")

        for method, info in results.items():
            if info:
                print(f"{method}: {info['symbol']} (decimals: {info['decimals']})")
            else:
                print(f"{method}: No information found")

        print("\n=== Final Determination ===")
        if token_info:
            print(f"Token Symbol: {token_info['info']['symbol']}")
            print(f"Decimals: {token_info['info']['decimals']}")
            print(f"Source: {token_info['source']}")
        else:
            print("Unable to determine token information")
            print("Recommendation: Manually specify token symbol and decimals when using transfer commands")


if __name__ == "__main__":
    main()
