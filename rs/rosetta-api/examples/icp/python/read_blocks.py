#!/bin/python3
"""
Read Blocks Example

This script demonstrates how to read blocks from the Internet Computer ledger
using the Rosetta API. It fetches the most recent block and the 10 previous blocks,
displaying their information.

Block information includes:
- Block index (height)
- Block hash
- Transactions within the block
- Timestamp

Examples:
    # Basic usage
    python3 read_blocks.py --node-address http://localhost:8081
"""

from rosetta_client import RosettaClient
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-address", type=str)
    args = parser.parse_args()
    
    client1 = RosettaClient(args.node_address)

    last_block = client1.get_last_block()
    last_block_index = last_block['block']['block_identifier']['index']
    print(f"Last block index: {last_block_index}")

    print(f"Previous 10 blocks:")
    for i in range(1,11):
        block = client1.get_block(last_block_index - i)
        print(block)

if __name__ == "__main__":
    main()