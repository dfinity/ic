#!/usr/bin/env python3
"""
Read ICRC-1 Blocks Example

This script demonstrates how to read blocks from an ICRC-1 ledger on the Internet Computer
using the Rosetta API. It can fetch the most recent block, a specific block by index or hash,
or a range of consecutive blocks.

Examples:
    # Fetch the latest block
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai
    
    # Fetch a specific block by index
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --block-index 1357691
    
    # Fetch a specific block by hash
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --block-hash 0415ed9ea78fed787e125179c99a7d0e599ee6e4cb0d610eed2c791e6e3f5e19
    
    # Fetch the latest block and previous N blocks
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --count 5
    
    # With raw JSON output
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --block-index 1357691 --raw
    
    # With verbose output
    python3 read_blocks.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --verbose
"""

from rosetta_client import RosettaClient
import argparse
import json
from datetime import datetime

def format_timestamp(timestamp_ms):
    """Format timestamp to human-readable format"""
    dt = datetime.fromtimestamp(timestamp_ms / 1000)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def print_block_summary(block_data, include_transactions=False, raw=False):
    """Print a summary of the block and optionally its transactions"""
    if raw:
        print(json.dumps(block_data, indent=2))
        return
    
    block = block_data.get('block', {})
    block_id = block.get('block_identifier', {})
    parent_id = block.get('parent_block_identifier', {})
    
    # Extract basic block info
    index = block_id.get('index', 'Unknown')
    hash_value = block_id.get('hash', 'Unknown')
    parent_index = parent_id.get('index', 'Unknown')
    parent_hash = parent_id.get('hash', 'Unknown')
    timestamp = block.get('timestamp', 0)
    
    # Format and print block header
    print(f"\n{'=' * 50}")
    print(f"Block #{index}")
    print(f"{'=' * 50}")
    print(f"Hash: {hash_value}")
    print(f"Parent: Block #{parent_index} ({parent_hash})")
    
    if timestamp:
        print(f"Timestamp: {format_timestamp(timestamp)}")
    
    # Print transaction summary if available
    transactions = block.get('transactions', [])
    tx_count = len(transactions)
    print(f"Transactions: {tx_count}")
    
    # Print transaction details if requested
    if include_transactions and tx_count > 0:
        print("\nTransactions:")
        for i, tx in enumerate(transactions):
            tx_id = tx.get('transaction_identifier', {})
            tx_hash = tx_id.get('hash', 'Unknown')
            
            # Count operations by type
            operations = tx.get('operations', [])
            op_types = {}
            for op in operations:
                op_type = op.get('type', 'Unknown')
                op_types[op_type] = op_types.get(op_type, 0) + 1
            
            # Format operation counts
            op_summary = ', '.join([f"{count} {op_type}" for op_type, count in op_types.items()])
            
            # Extract memo if present
            memo = None
            if 'metadata' in tx and 'memo' in tx['metadata']:
                memo_bytes = tx['metadata']['memo']
                if isinstance(memo_bytes, list):
                    try:
                        # Try to convert memo bytes to ASCII if possible
                        memo = ''.join([chr(b) for b in memo_bytes if 32 <= b <= 126])
                    except:
                        memo = str(memo_bytes)
            
            print(f"  {i+1}. Hash: {tx_hash}")
            print(f"     Operations: {op_summary}")
            if memo:
                print(f"     Memo: {memo}")

def main():
    parser = argparse.ArgumentParser(description='Read blocks from an ICRC-1 ledger using Rosetta API')
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--canister-id", type=str, required=True, help="Canister ID of the ICRC-1 ledger")
    parser.add_argument("--block-index", type=int, help="Specific block index to fetch")
    parser.add_argument("--block-hash", type=str, help="Specific block hash to fetch")
    parser.add_argument("--count", type=int, default=1, help="Number of blocks to fetch, starting from latest or specified block")
    parser.add_argument("--include-tx", action="store_true", help="Include transaction details")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose API debug output")
    
    args = parser.parse_args()
    
    client = RosettaClient(args.node_address, args.canister_id)
    
    # Case 1: Fetch a specific block by index or hash
    if args.block_index is not None or args.block_hash is not None:
        print(f"Fetching block", end=" ")
        if args.block_index is not None:
            print(f"#{args.block_index}", end=" ")
        if args.block_hash is not None:
            print(f"with hash {args.block_hash}", end=" ")
        print("...")
        
        block_data = client.get_block(args.block_index, args.block_hash, verbose=args.verbose)
        print_block_summary(block_data, include_transactions=args.include_tx, raw=args.raw)
        
        if args.count > 1:
            print("\nWarning: --count is ignored when fetching a specific block")
    
    # Case 2: Fetch the latest block and previous blocks
    else:
        print(f"Fetching the latest {args.count} block(s)...")
        
        # Get the latest block first
        latest_block = client.get_block(verbose=args.verbose)
        print_block_summary(latest_block, include_transactions=args.include_tx, raw=args.raw)
        
        # If count > 1, fetch previous blocks
        if args.count > 1:
            latest_index = latest_block['block']['block_identifier']['index']
            
            for i in range(1, args.count):
                # Skip if we would go below block 0
                if latest_index - i < 0:
                    break
                    
                block_data = client.get_block(latest_index - i, verbose=args.verbose)
                print_block_summary(block_data, include_transactions=args.include_tx, raw=args.raw)

if __name__ == "__main__":
    main() 