#!/usr/bin/env python3
"""
Get ICRC-1 Network Information Example

This script demonstrates how to fetch network information from an ICRC-1 ledger
using the Rosetta API. It retrieves and displays:

1. Available networks (blockchain identifiers)
2. Network status (current block, genesis block, peers)
3. Network options (supported features, operations, errors)

This information is useful for developers who want to understand the capabilities
and current state of the ICRC-1 ledger network.

Examples:
    # Basic usage
    python3 get_network_info.py --node-address http://localhost:8082 --canister-id <canister-id>

    # With raw JSON output
    python3 get_network_info.py --node-address http://localhost:8082 --canister-id <canister-id> --raw

    # With verbose output
    python3 get_network_info.py --node-address http://localhost:8082 --canister-id <canister-id> --verbose

Required Parameters:
    --node-address: URL of the Rosetta API endpoint
    --canister-id: Canister ID of the ICRC-1 ledger

"""

import argparse
import json
from datetime import datetime

from rosetta_client import RosettaClient


def format_timestamp(timestamp_ms):
    """Format a Unix timestamp (in milliseconds) to a human-readable string"""
    if not timestamp_ms:
        return "N/A"
    return datetime.fromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def main():
    parser = argparse.ArgumentParser(description="Fetch ICRC-1 network information via Rosetta API")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--canister-id", type=str, required=True, help="Canister ID of the ICRC-1 ledger")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")

    args = parser.parse_args()

    client = RosettaClient(node_address=args.node_address, canister_id=args.canister_id, verbose=args.verbose)

    # Get network list
    print("Fetching available networks...")
    networks = client.list_networks(verbose=args.verbose)

    if args.raw:
        print("\nNetwork List Response:")
        print(json.dumps(networks, indent=2))
    else:
        print("\nAvailable Networks:")
        for i, network in enumerate(networks):
            print(f"  {i+1}. Blockchain: {network.get('blockchain', 'Unknown')}")
            print(f"     Network: {network.get('network', 'Unknown')}")

    # Get network status
    print("\nFetching network status...")
    status = client.get_status(verbose=args.verbose)

    if args.raw:
        print("\nNetwork Status Response:")
        print(json.dumps(status, indent=2))
    else:
        print("\nNetwork Status:")

        # Current block
        current_block = status.get("current_block_identifier", {})
        current_block_index = current_block.get("index", "Unknown")
        current_block_hash = current_block.get("hash", "Unknown")

        # Current block timestamp
        current_time = status.get("current_block_timestamp", 0)

        # Genesis block
        genesis_block = status.get("genesis_block_identifier", {})
        genesis_block_index = genesis_block.get("index", "Unknown")
        genesis_block_hash = genesis_block.get("hash", "Unknown")

        # Peers
        peers = status.get("peers", [])

        print(f"  Current Block Index: {current_block_index}")
        print(f"  Current Block Hash: {current_block_hash}")
        print(f"  Current Block Time: {format_timestamp(current_time)}")
        print(f"  Genesis Block Index: {genesis_block_index}")
        print(f"  Genesis Block Hash: {genesis_block_hash}")
        print(f"  Connected Peers: {len(peers)}")

        if peers:
            print("\n  Peer List:")
            for i, peer in enumerate(peers):
                peer_id = peer.get("peer_id", "Unknown")
                metadata = peer.get("metadata", {})
                print(f"    {i+1}. Peer ID: {peer_id}")
                if metadata:
                    for key, value in metadata.items():
                        print(f"       {key}: {value}")

    # Get network options
    print("\nFetching network options...")
    options = client.get_options(verbose=args.verbose)

    if args.raw:
        print("\nNetwork Options Response:")
        print(json.dumps(options, indent=2))
    else:
        print("\nNetwork Options:")

        # Version information
        version = options.get("version", {})
        node_version = version.get("node_version", "Unknown")
        middleware_version = version.get("middleware_version", "Unknown")
        rosetta_version = version.get("rosetta_version", "Unknown")

        # Operation types and statuses
        allowed_ops = options.get("allow", {})
        operation_types = allowed_ops.get("operation_types", [])
        operation_statuses = allowed_ops.get("operation_statuses", [])
        errors = allowed_ops.get("errors", [])

        print(f"  Node Version: {node_version}")
        print(f"  Middleware Version: {middleware_version}")
        print(f"  Rosetta Version: {rosetta_version}")

        print(f"\n  Supported Operation Types: {', '.join(operation_types)}")

        print("\n  Operation Statuses:")
        for status in operation_statuses:
            status_text = status.get("status", "Unknown")
            successful = status.get("successful", False)
            print(f"    - {status_text} (Successful: {successful})")

        if errors:
            print("\n  Supported Error Types:")
            for error in errors:
                error_code = error.get("code", "Unknown")
                error_message = error.get("message", "Unknown")
                retriable = error.get("retriable", False)
                print(f"    - {error_code}: {error_message} (Retriable: {retriable})")

        # Show supported currencies
        if "allow" in options and "currencies" in options["allow"]:
            currencies = options["allow"].get("currencies", [])
            if currencies:
                print("\n  Supported Currencies:")
                for currency in currencies:
                    symbol = currency.get("symbol", "Unknown")
                    decimals = currency.get("decimals", 0)
                    print(f"    - {symbol} (Decimals: {decimals})")


if __name__ == "__main__":
    main()
