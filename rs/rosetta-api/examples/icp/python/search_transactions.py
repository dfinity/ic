#!/usr/bin/env python3
"""
Search Transactions Example

This script demonstrates how to search for transactions on the Internet Computer
using the Rosetta API. It supports the following search methods:

1. Fetch a specific transaction by block index and transaction hash
2. Search for transactions by account
3. List transactions from the latest block

Transaction information includes:
- Transaction hash
- Operations (transfers, fees)
- Metadata (timestamp, memo)
- Amounts and accounts involved

Examples:
    # Get a specific transaction
    python3 search_transactions.py --node-address http://localhost:8081 --block-index 9840566 --transaction-hash 93a19bfa37db0200cec77281cd8a0602a4375a7367338e7c6973f93a42e6eb5e

    # Search transactions for an account
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4

    # Search with pagination (limit and offset)
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --limit 5 --offset 10

    # Get transactions from the latest block
    python3 search_transactions.py --node-address http://localhost:8081

    # With raw JSON output
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --raw

    # With verbose output
    python3 search_transactions.py --node-address http://localhost:8081 --account-id 8b84c3a3529d02a9decb5b1a27e7c8d886e17e07ea0a538269697ef09c2a27b4 --verbose
"""

from rosetta_client import RosettaClient
import argparse
import json
from datetime import datetime

def format_timestamp(timestamp_ns):
    """Format a nanosecond timestamp to a human-readable string"""
    if not timestamp_ns:
        return "N/A"
    return datetime.fromtimestamp(timestamp_ns / 10**9).strftime('%Y-%m-%d %H:%M:%S')

def format_amount(amount):
    """Format an amount to a human-readable string"""
    if not amount:
        return "N/A"
    
    value = int(amount.get("value", 0))
    currency = amount.get("currency", {})
    symbol = currency.get("symbol", "")
    decimals = int(currency.get("decimals", 0))
    
    formatted_value = value / 10**decimals if decimals > 0 else value
    return f"{formatted_value} {symbol}"

def main():
    parser = argparse.ArgumentParser(description='Search for transactions using the Rosetta API')
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--account-id", type=str, help="Account identifier to search transactions for")
    parser.add_argument("--block-index", type=int, help="Get transactions for a specific block index")
    parser.add_argument("--transaction-hash", type=str, help="Get a specific transaction by hash (requires --block-index)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of transactions to return")
    parser.add_argument("--offset", type=int, help="Offset for pagination")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")
    
    args = parser.parse_args()
    
    client = RosettaClient(args.node_address)
    
    # Case 1: Get a specific transaction by block index and transaction hash
    if args.block_index is not None and args.transaction_hash:
        print(f"Fetching transaction {args.transaction_hash} from block {args.block_index}...")
        response = client.get_transaction(args.block_index, args.transaction_hash, verbose=args.verbose)
        
        if args.raw:
            print(json.dumps(response, indent=2))
            return
        
        transaction = response.get("transaction", {})
        print("\n=== Transaction Details ===")
        print(f"Hash: {transaction.get('transaction_identifier', {}).get('hash', 'Unknown')}")
        
        # Process operations
        operations = transaction.get("operations", [])
        print(f"\nOperations ({len(operations)}):")
        
        for i, op in enumerate(operations):
            op_index = op.get("operation_identifier", {}).get("index", i)
            op_type = op.get("type", "Unknown")
            op_status = op.get("status", "Unknown")
            
            account = op.get("account", {}).get("address", "Unknown")
            amount = format_amount(op.get("amount", {}))
            
            print(f"\n  Operation {op_index} ({op_type}):")
            print(f"    Status: {op_status}")
            print(f"    Account: {account}")
            print(f"    Amount: {amount}")
            
            # Show metadata if available
            if "metadata" in op:
                print("    Metadata:")
                for key, value in op["metadata"].items():
                    print(f"      {key}: {value}")
        
        # Show transaction metadata
        if "metadata" in transaction:
            metadata = transaction["metadata"]
            print("\nTransaction Metadata:")
            
            if "block_height" in metadata:
                print(f"  Block Height: {metadata['block_height']}")
            
            if "memo" in metadata:
                print(f"  Memo: {metadata['memo']}")
                
            if "timestamp" in metadata:
                print(f"  Timestamp: {format_timestamp(metadata['timestamp'])}")
                
            # Other metadata
            for key, value in metadata.items():
                if key not in ["block_height", "memo", "timestamp"]:
                    print(f"  {key}: {value}")
    
    # Case 2: Search for transactions by account
    elif args.account_id:
        print(f"Searching for transactions involving account {args.account_id}...")
        response = client.search_transactions(
            address=args.account_id, 
            start_index=args.offset,
            limit=args.limit,
            verbose=args.verbose
        )
        
        if args.raw:
            print(json.dumps(response, indent=2))
            return
        
        transactions = response.get("transactions", [])
        total = response.get("total_count", 0)
        print(f"\nFound {total} transaction(s), showing {len(transactions)}")
        
        for i, tx_data in enumerate(transactions):
            block = tx_data.get("block_identifier", {})
            tx = tx_data.get("transaction", {})
            
            tx_hash = tx.get("transaction_identifier", {}).get("hash", "Unknown")
            block_index = block.get("index", "Unknown")
            
            print(f"\n--- Transaction {i+1} ---")
            print(f"Hash: {tx_hash}")
            print(f"Block: {block_index}")
            
            # Show operations summary
            operations = tx.get("operations", [])
            print(f"Operations: {len(operations)}")
            
            # Operation types summary
            op_types = {}
            for op in operations:
                op_type = op.get("type", "Unknown")
                op_types[op_type] = op_types.get(op_type, 0) + 1
            
            print("Operation Types:")
            for op_type, count in op_types.items():
                print(f"  - {op_type}: {count}")
            
            # Show metadata if available
            if "metadata" in tx:
                metadata = tx["metadata"]
                if "timestamp" in metadata:
                    print(f"Timestamp: {format_timestamp(metadata['timestamp'])}")
                if "memo" in metadata:
                    print(f"Memo: {metadata['memo']}")
            
            print(f"To view full transaction details: --block-index {block_index} --transaction-hash {tx_hash}")
    
    # Case 3: No specific filters provided, get the latest block and show its transactions
    else:
        print("No search criteria provided. Fetching the latest block...")
        response = client.get_last_block(verbose=args.verbose)
        
        if args.raw:
            print(json.dumps(response, indent=2))
            return
        
        block = response.get("block", {})
        block_identifier = block.get("block_identifier", {})
        block_index = block_identifier.get("index", "Unknown")
        block_hash = block_identifier.get("hash", "Unknown")
        
        transactions = block.get("transactions", [])
        
        print(f"\n=== Latest Block ===")
        print(f"Index: {block_index}")
        print(f"Hash: {block_hash}")
        print(f"Transactions: {len(transactions)}")
        
        for i, tx in enumerate(transactions[:args.limit]):
            tx_hash = tx.get("transaction_identifier", {}).get("hash", "Unknown")
            
            print(f"\n--- Transaction {i+1} ---")
            print(f"Hash: {tx_hash}")
            
            # Show operations summary
            operations = tx.get("operations", [])
            print(f"Operations: {len(operations)}")
            
            # Operation types summary
            op_types = {}
            for op in operations:
                op_type = op.get("type", "Unknown")
                op_types[op_type] = op_types.get(op_type, 0) + 1
            
            print("Operation Types:")
            for op_type, count in op_types.items():
                print(f"  - {op_type}: {count}")
            
            # Show metadata if available
            if "metadata" in tx:
                metadata = tx["metadata"]
                if "timestamp" in metadata:
                    print(f"Timestamp: {format_timestamp(metadata['timestamp'])}")
                if "memo" in metadata:
                    print(f"Memo: {metadata['memo']}")
            
            print(f"To view full transaction details: --block-index {block_index} --transaction-hash {tx_hash}")
        
        if len(transactions) > args.limit:
            print(f"\nShowing {args.limit} of {len(transactions)} transactions. Use --limit to see more.")

if __name__ == "__main__":
    main() 