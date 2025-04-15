#!/usr/bin/env python3
"""
Search ICRC-1 Transactions Example

This script demonstrates how to search for transactions on an ICRC-1 ledger
using the Rosetta API. It supports the following search methods:

1. Fetch a specific transaction by block index and transaction hash
2. Search for transactions by principal
3. List transactions from the latest block

Transaction information includes:
- Transaction hash
- Operations (transfers, fees)
- Metadata (timestamp, memo)
- Amounts and accounts involved

Examples:
    # Get a specific transaction
    python3 search_transactions.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --block-index 1357691 --transaction-hash 700481a99b9a10cf4c4d037141ae5f1472fefe1f5be6b43d02577e398da4bdfe

    # Search transactions for a principal
    python3 search_transactions.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai

    # Search with pagination (limit and offset)
    python3 search_transactions.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai --limit 5 --offset 10

    # Get transactions from the latest block
    python3 search_transactions.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai

    # With raw JSON output
    python3 search_transactions.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai --raw

    # With verbose output
    python3 search_transactions.py --node-address http://localhost:8082 --canister-id mxzaz-hqaaa-aaaar-qaada-cai --principal-id xmiu5-jqaaa-aaaag-qbz7q-cai --verbose
"""

from rosetta_client import RosettaClient
import argparse
import json
from datetime import datetime

def format_timestamp(timestamp_ms):
    """Format a millisecond timestamp to a human-readable string"""
    if not timestamp_ms:
        return "N/A"
    return datetime.fromtimestamp(timestamp_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')

def format_amount(amount):
    """Format an amount to a human-readable string"""
    if not amount:
        return "N/A"
    
    value = int(amount.get("value", 0))
    currency = amount.get("currency", {})
    symbol = currency.get("symbol", "")
    decimals = int(currency.get("decimals", 0))
    
    formatted_value = value / 10**decimals if decimals > 0 else value
    return f"{formatted_value} {symbol} ({value} raw)"

def format_memo(memo):
    """Format a memo to a readable string"""
    if not memo:
        return None
        
    if isinstance(memo, list):
        try:
            # Try to convert memo bytes to ASCII if possible
            printable_memo = ''.join([chr(b) for b in memo if 32 <= b <= 126])
            if printable_memo:
                return f"{printable_memo} (hex: {' '.join([hex(b)[2:].zfill(2) for b in memo])})"
            else:
                return f"hex: {' '.join([hex(b)[2:].zfill(2) for b in memo])}"
        except:
            return str(memo)
    else:
        return str(memo)

def main():
    parser = argparse.ArgumentParser(description='Search for ICRC-1 transactions using the Rosetta API')
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--canister-id", type=str, required=True, help="Canister ID of the ICRC-1 ledger")
    parser.add_argument("--principal-id", type=str, help="Principal identifier to search transactions for")
    parser.add_argument("--sub-account", type=str, help="Subaccount in hex (default is all zeros)")
    parser.add_argument("--block-index", type=int, help="Get transactions for a specific block index")
    parser.add_argument("--transaction-hash", type=str, help="Get a specific transaction by hash (requires --block-index)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of transactions to return")
    parser.add_argument("--offset", type=int, help="Offset for pagination")
    parser.add_argument("--raw", action="store_true", help="Display raw JSON response")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    client = RosettaClient(args.node_address, args.canister_id)
    
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
            
            account = op.get("account", {})
            principal = account.get("address", "Unknown")
            subaccount = account.get("sub_account", {}).get("address", "Default")
            
            amount = format_amount(op.get("amount", {}))
            
            print(f"\n  Operation {op_index} ({op_type}):")
            print(f"    Status: {op_status}")
            print(f"    Principal: {principal}")
            print(f"    Subaccount: {subaccount}")
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
            
            if "memo" in metadata:
                memo_str = format_memo(metadata["memo"])
                if memo_str:
                    print(f"  Memo: {memo_str}")
                
            if "created_at_time" in metadata:
                created_time = metadata["created_at_time"]
                if isinstance(created_time, int):
                    print(f"  Created At: {format_timestamp(created_time)}")
                else:
                    print(f"  Created At: {created_time}")
                
            # Other metadata
            for key, value in metadata.items():
                if key not in ["memo", "created_at_time"]:
                    print(f"  {key}: {value}")
    
    # Case 2: Search for transactions by principal
    elif args.principal_id:
        print(f"Searching for transactions involving principal {args.principal_id}")
        if args.sub_account:
            print(f"with subaccount {args.sub_account}...")
        else:
            print("...")
            
        response = client.search_transactions(
            principal=args.principal_id,
            subaccount=args.sub_account, 
            limit=args.limit,
            offset=args.offset,
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
            
            # Show amount summary
            transfers = [op for op in operations if op.get("type") == "TRANSFER" and op.get("amount", {}).get("value", "0")[0] != "-"]
            if transfers:
                for transfer in transfers:
                    amount = format_amount(transfer.get("amount", {}))
                    account = transfer.get("account", {})
                    principal = account.get("address", "Unknown")
                    subaccount = account.get("sub_account", {}).get("address", "Default")
                    print(f"Amount: {amount} to {principal} (subaccount {subaccount})")
            
            # Show metadata if available
            if "metadata" in tx:
                metadata = tx["metadata"]
                if "memo" in metadata:
                    memo_str = format_memo(metadata["memo"])
                    if memo_str:
                        print(f"Memo: {memo_str}")
                        
                if "created_at_time" in metadata:
                    created_time = metadata["created_at_time"]
                    if isinstance(created_time, int):
                        print(f"Created At: {format_timestamp(created_time)}")
                    else:
                        print(f"Created At: {created_time}")
            
            print(f"To view full transaction details: --block-index {block_index} --transaction-hash {tx_hash}")
    
    # Case 3: No specific filters provided, get the latest block and show its transactions
    else:
        print("No search criteria provided. Fetching the latest block...")
        response = client.get_block(verbose=args.verbose)
        
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
                
            # Show amount summary
            transfers = [op for op in operations if op.get("type") == "TRANSFER" and op.get("amount", {}).get("value", "0")[0] != "-"]
            if transfers:
                for transfer in transfers:
                    amount = format_amount(transfer.get("amount", {}))
                    account = transfer.get("account", {})
                    principal = account.get("address", "Unknown")
                    subaccount = account.get("sub_account", {}).get("address", "Default")
                    print(f"Amount: {amount} to {principal}")
            
            # Show metadata if available
            if "metadata" in tx:
                metadata = tx["metadata"]
                if "memo" in metadata:
                    memo_str = format_memo(metadata["memo"])
                    if memo_str:
                        print(f"Memo: {memo_str}")
                        
                if "created_at_time" in metadata:
                    created_time = metadata["created_at_time"]
                    if isinstance(created_time, int):
                        print(f"Created At: {format_timestamp(created_time)}")
                    else:
                        print(f"Created At: {created_time}")
            
            print(f"To view full transaction details: --block-index {block_index} --transaction-hash {tx_hash}")
        
        if len(transactions) > args.limit:
            print(f"\nShowing {args.limit} of {len(transactions)} transactions. Use --limit to see more.")

if __name__ == "__main__":
    main() 