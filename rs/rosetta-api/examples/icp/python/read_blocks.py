#!/usr/bin/env python3
"""
Read Blocks Example

This script demonstrates how to read blocks from the Internet Computer ledger
using the Rosetta API. It fetches the most recent block and the requested number
of previous blocks, displaying their information.

Block information includes:
- Block index (height)
- Block hash
- Transactions within the block
- Timestamp

Examples:
    # Basic usage (fetches 10 blocks by default)
    python3 read_blocks.py --node-address http://localhost:8081

    # Fetch a specific number of blocks
    python3 read_blocks.py --node-address http://localhost:8081 --block-count 5

"""

import argparse

from rosetta_client import RosettaClient


def main():
    parser = argparse.ArgumentParser(description="Read blocks from the Internet Computer ledger")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--block-count", type=int, default=10, help="Number of previous blocks to fetch (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    client = RosettaClient(args.node_address)

    # Get the last block to determine the current height
    last_block = client.get_last_block(verbose=args.verbose)
    last_block_index = last_block["block"]["block_identifier"]["index"]
    print(f"Last block index: {last_block_index}")

    # Determine how many blocks to fetch
    block_count = min(args.block_count, last_block_index)

    if block_count < args.block_count:
        print(
            f"Warning: Chain height is {last_block_index}, which is less than the requested {args.block_count} blocks."
        )
        print(f"Fetching {block_count} blocks instead.")

    print(f"\nFetching {block_count} previous blocks:")
    blocks_fetched = 0

    for i in range(1, block_count + 1):
        try:
            block_index = last_block_index - i
            if block_index < 0:
                break

            block = client.get_block(block_index, verbose=args.verbose)
            block_hash = block["block"]["block_identifier"]["hash"]
            timestamp = block["block"]["timestamp"]
            tx_count = len(block["block"]["transactions"]) if "transactions" in block["block"] else 0

            print(f"\nBlock {block_index}:")
            print(f"  Hash: {block_hash}")
            print(f"  Timestamp: {timestamp}")
            print(f"  Transaction count: {tx_count}")

            blocks_fetched += 1
        except Exception as e:
            print(f"Error fetching block at index {last_block_index - i}: {e}")

    print(f"\nSuccessfully fetched {blocks_fetched} blocks.")


if __name__ == "__main__":
    main()
