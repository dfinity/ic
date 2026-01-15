#!/usr/bin/env python3
"""
Search Transactions Example

This script demonstrates how to search for transactions using the Internet Computer
Rosetta API. It supports searching by:
- Account identifier (from/to/spender account)
- Transaction hash
- Operation type

The search results include block information and transaction details.

Examples:
    # Search transactions for a specific account
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4

    # Search transactions by transaction hash
    python3 search_transactions.py --node-address http://localhost:8081 --transaction-hash 3adee70e84be87a5c21c8d42d953e6d88249a08e53e4aaad7a70ffd0a266fb63

    # Search transactions by operation type
    python3 search_transactions.py --node-address http://localhost:8081 --operation-type TRANSFER

    # Limit the number of results
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --limit 5

    # With verbose output
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --verbose

"""

import argparse
import json
from datetime import datetime

from rosetta_client import RosettaClient


def format_timestamp(timestamp):
    """Format a Unix timestamp to a human-readable string"""
    if not timestamp:
        return "N/A"

    try:
        # Handle nanosecond timestamps (Internet Computer uses nanosecond precision)
        # If the timestamp is too large for milliseconds, it might be in nanoseconds
        if timestamp > 100000000000000:  # Likely nanoseconds
            timestamp = timestamp / 1000000000  # Convert to seconds
        else:
            timestamp = timestamp / 1000  # Convert milliseconds to seconds

        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError):
        # Fallback for timestamps out of range
        return f"Raw timestamp: {timestamp}"


def format_operation(operation, currency_symbol):
    """Format an operation for display"""
    op_type = operation.get("type", "Unknown")
    account = operation.get("account", {}).get("address", "Unknown")

    amount_info = operation.get("amount", {})
    if amount_info:
        value = amount_info.get("value", "0")
        # Add plus sign for positive values for clarity
        if value and not value.startswith("-"):
            value = f"+{value}"

        currency = amount_info.get("currency", {})
        symbol = currency.get("symbol", currency_symbol)
        decimals = currency.get("decimals", 8)

        # Convert e8s to ICP for display
        if value:
            amount_e8s = int(value)
            amount_icp = amount_e8s / 10**decimals
            return f"{op_type}: {account} {amount_icp} {symbol} ({amount_e8s} e8s)"

    return f"{op_type}: {account}"


def main():
    parser = argparse.ArgumentParser(description="Search for transactions using Rosetta API")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--account-id", type=str, help="Account identifier to search transactions for")
    parser.add_argument("--transaction-hash", type=str, help="Transaction hash to search for")
    parser.add_argument("--operation-type", type=str, help="Operation type to search for (e.g., TRANSFER, MINT)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of transactions to return")
    parser.add_argument("--offset", type=int, help="Starting point for pagination")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")

    args = parser.parse_args()

    # Validate input
    if not (args.account_id or args.transaction_hash or args.operation_type):
        parser.error("At least one of --account-id, --transaction-hash, or --operation-type must be provided")

    client = RosettaClient(args.node_address)

    # Perform the search
    print("Searching for transactions...")
    response = client.search_transactions(
        address=args.account_id,
        transaction_hash=args.transaction_hash,
        operation_type=args.operation_type,
        start_index=args.offset,
        limit=args.limit,
        verbose=args.verbose,
    )

    if args.raw:
        print(json.dumps(response, indent=2))
        return

    # Extract and display transaction information
    transactions = response.get("transactions", [])
    total_count = response.get("total_count", 0)
    next_offset = response.get("next_offset")

    print(f"\nFound {total_count} matching transaction(s)")
    print(f"Displaying {len(transactions)} result(s)")

    for i, tx_data in enumerate(transactions):
        block_info = tx_data.get("block_identifier", {})
        block_index = block_info.get("index", "Unknown")
        block_hash = block_info.get("hash", "Unknown")

        transaction = tx_data.get("transaction", {})
        tx_hash = transaction.get("transaction_identifier", {}).get("hash", "Unknown")
        tx_metadata = transaction.get("metadata", {})
        operations = transaction.get("operations", [])

        # Get the timestamp if available
        timestamp = transaction.get("metadata", {}).get("timestamp")

        print(f"\n--- Transaction {i+1} ---")
        print(f"Block: {block_index}")
        print(f"Block Hash: {block_hash}")
        print(f"Transaction Hash: {tx_hash}")

        if timestamp:
            print(f"Timestamp: {format_timestamp(timestamp)}")

        if operations:
            print("\nOperations:")
            for j, op in enumerate(operations):
                print(f"  {j+1}. {format_operation(op, client.currency_symbol)}")

        # Show any additional metadata if available
        if tx_metadata and args.verbose:
            print("\nMetadata:")
            for key, value in tx_metadata.items():
                if key != "operations" and key != "timestamp":
                    print(f"  {key}: {value}")

    # Show pagination information
    if next_offset is not None:
        print(f"\nMore results available. Use --offset {next_offset} to view the next page.")


if __name__ == "__main__":
    main()
