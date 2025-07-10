#!/usr/bin/env python3
"""
Read ICRC-1 Blocks Example

This script demonstrates how to read blocks from an ICRC-1 ledger on the Internet Computer
using the Rosetta API. It can fetch the most recent block, a specific block by index or hash,
or a range of consecutive blocks.

Examples:
    # Fetch the latest block
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id <canister-id>

    # Fetch a specific block by index
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id <canister-id> --block-index <block-number>

    # Fetch a specific block by hash
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id <canister-id> --block-hash <block-hash>

    # Fetch the latest block and previous N blocks
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id <canister-id> --count 5

    # With raw JSON output
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id <canister-id> --block-index <block-number> --raw

    # With verbose output
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id <canister-id> --verbose

Required Parameters:
    --node-address: URL of the Rosetta API endpoint
    --canister-id: Canister ID of the ICRC-1 ledger

"""

import argparse
import json
import os
import sys
from datetime import datetime

# Add the parent directory to the path to allow importing the common client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rosetta_client import RosettaClient


def format_operation(op):
    """Format a single operation for display"""
    status = op.get("status", "unknown")
    amount = op.get("amount", {})

    if amount:
        value = amount.get("value", "0")
        currency = amount.get("currency", {})
        symbol = currency.get("symbol", "Unknown")
        decimals = currency.get("decimals", 0)

        # Convert value to float and adjust according to decimals
        try:
            numeric_value = int(value)
            adjusted_value = numeric_value / (10**decimals)
            formatted_value = (
                f"{adjusted_value:.{decimals}f}".rstrip("0").rstrip(".")
                if "." in f"{adjusted_value:.{decimals}f}"
                else f"{adjusted_value:.0f}"
            )
        except ValueError:
            formatted_value = value

        return f"{op['type']} {formatted_value} {symbol} ({status})"
    else:
        return f"{op['type']} ({status})"


def format_account(account):
    """Format an account for display"""
    if not account:
        return "None"

    addr = account.get("address", "")
    sub_account = account.get("sub_account", {})
    sub = sub_account.get("address", "") if sub_account else ""

    if sub:
        return f"{addr} (sub:{sub})"
    return addr


def format_transaction(tx):
    """Format a transaction for display"""
    result = []
    ops = tx.get("operations", [])

    if len(ops) > 0:
        result.append(f"  Operations: {len(ops)}")
        for i, op in enumerate(ops):
            account = format_account(op.get("account", {}))
            result.append(f"    {i+1}. {format_operation(op)}")
            result.append(f"       Account: {account}")

    metadata = tx.get("metadata", {})
    if metadata:
        memo = metadata.get("memo", [])
        if memo:
            result.append(f"  Memo: {memo}")

    return "\n".join(result)


def format_block(block, show_txs=True):
    """Format a block for display"""
    result = []

    # The response from the API contains a 'block' field that contains the actual block data
    if "block" in block:
        block = block["block"]

    # Get block identifier
    block_id = block.get("block_identifier", {})
    block_parent = block.get("parent_block_identifier", {})
    timestamp = block.get("timestamp", 0)

    # Convert timestamp to date (if in milliseconds)
    if timestamp > 1000000000000:  # If in milliseconds
        timestamp = timestamp / 1000
    dt = datetime.fromtimestamp(timestamp)

    # Format basic block info
    result.append(f"Block Index: {block_id.get('index', 'unknown')}")
    result.append(f"Block Hash: {block_id.get('hash', 'unknown')}")
    result.append(f"Parent Block: {block_parent.get('index', 'unknown')}")
    result.append(f"Timestamp: {dt.isoformat()}")

    # Add transactions if requested
    if show_txs:
        txs = block.get("transactions", [])
        if txs:
            result.append(f"\nTransactions: {len(txs)}")
            for i, tx in enumerate(txs):
                result.append(f"\nTransaction {i+1}:")
                result.append(format_transaction(tx))
        else:
            result.append("\nNo transactions in this block")

    return "\n".join(result)


def main():
    parser = argparse.ArgumentParser(description="Read blocks from an ICRC-1 ledger")

    parser.add_argument(
        "--node-address", type=str, required=True, help="Rosetta API endpoint URL (e.g., http://localhost:8082)"
    )
    parser.add_argument("--canister-id", type=str, required=True, help="ICRC-1 canister ID")
    parser.add_argument("--block-index", type=int, help="Specific block index to fetch")
    parser.add_argument("--block-hash", type=str, help="Specific block hash to fetch")
    parser.add_argument("--count", type=int, default=1, help="Number of blocks to fetch (default: 1)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON response")

    args = parser.parse_args()

    # Initialize the Rosetta client
    client = RosettaClient(node_address=args.node_address, canister_id=args.canister_id, verbose=args.verbose)

    # Track blocks we've fetched
    fetched_blocks = []

    try:
        # Case 1: Fetch by specific hash
        if args.block_hash:
            block = client.get_block(block_index=None, block_hash=args.block_hash, verbose=args.verbose)
            fetched_blocks.append(block)

        # Case 2: Fetch specific block index
        elif args.block_index is not None:
            block = client.get_block(block_index=args.block_index, block_hash=None, verbose=args.verbose)
            fetched_blocks.append(block)

        # Case 3: Fetch latest block and potentially previous ones
        else:
            # Get the latest block first
            status = client.get_status(verbose=args.verbose)

            # Try to get the latest index from sync_status or current_block_identifier
            latest_index = 0
            if "sync_status" in status and "current_index" in status["sync_status"]:
                latest_index = status["sync_status"]["current_index"]
            elif "current_block_identifier" in status and "index" in status["current_block_identifier"]:
                latest_index = status["current_block_identifier"]["index"]
            else:
                # If we can't determine the latest index, try to get the latest block directly
                block = client.get_block(block_index=None, block_hash=None, verbose=args.verbose)
                if (
                    "block" in block
                    and "block_identifier" in block["block"]
                    and "index" in block["block"]["block_identifier"]
                ):
                    latest_index = block["block"]["block_identifier"]["index"]
                else:
                    raise Exception("Could not determine the latest block index")

            # Fetch requested number of blocks
            for i in range(args.count):
                idx = latest_index - i
                if idx < 0:
                    break
                block = client.get_block(block_index=idx, block_hash=None, verbose=args.verbose)
                fetched_blocks.append(block)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Display the results
    if args.raw:
        if len(fetched_blocks) == 1:
            print(json.dumps(fetched_blocks[0], indent=2))
        else:
            print(json.dumps(fetched_blocks, indent=2))
    else:
        for i, block in enumerate(fetched_blocks):
            if i > 0:
                print("\n" + "=" * 50 + "\n")
            print(format_block(block))


if __name__ == "__main__":
    main()
