#!/usr/bin/env python3
"""
Transfer ICRC-1 Tokens Example

This script demonstrates how to transfer ICRC-1 tokens from one account to another
using the Internet Computer Rosetta API. It shows the initial balances of both
accounts, performs the transfer, and then displays the final balances to confirm
the transaction was successful.

To use this script, you need:
1. A Rosetta node address
2. The canister ID of the ICRC-1 ledger
3. A private key file for the sender account
4. The sender's principal ID and optional subaccount
5. The recipient's principal ID and optional subaccount
6. The amount to transfer
7. The fee to include

Examples:
    # Basic transfer of 0.01 ckBTC with standard fee
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id mxzaz-hqaaa-aaaar-qaada-cai \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --from-principal lrf2i-zba54-pygwt-tbi75-zvlz4-7gfhh-ylcrq-2zh73-6brgn-45jy5-cae \\
                       --to-principal xmiu5-jqaaa-aaaag-qbz7q-cai \\
                       --amount 1000000 \\
                       --fee 100000

    # Transfer with subaccounts
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id mxzaz-hqaaa-aaaar-qaada-cai \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --from-principal lrf2i-zba54-pygwt-tbi75-zvlz4-7gfhh-ylcrq-2zh73-6brgn-45jy5-cae \\
                       --from-subaccount 0000000000000000000000000000000000000000000000000000000000000000 \\
                       --to-principal xmiu5-jqaaa-aaaag-qbz7q-cai \\
                       --to-subaccount 0000000000000000000000000000000000000000000000000000000000000000 \\
                       --amount 1000000 \\
                       --fee 100000

    # With memo
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id mxzaz-hqaaa-aaaar-qaada-cai \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --from-principal lrf2i-zba54-pygwt-tbi75-zvlz4-7gfhh-ylcrq-2zh73-6brgn-45jy5-cae \\
                       --to-principal xmiu5-jqaaa-aaaag-qbz7q-cai \\
                       --amount 1000000 \\
                       --fee 100000 \\
                       --memo "Payment for services"

    # With verbose output for debugging
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id mxzaz-hqaaa-aaaar-qaada-cai \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --from-principal lrf2i-zba54-pygwt-tbi75-zvlz4-7gfhh-ylcrq-2zh73-6brgn-45jy5-cae \\
                       --to-principal xmiu5-jqaaa-aaaag-qbz7q-cai \\
                       --amount 1000000 \\
                       --fee 100000 \\
                       --verbose
"""

from rosetta_client import RosettaClient
import time
import argparse

def parse_balance(balance):
    """Parse the balance response and return a formatted string"""
    value = int(balance["balances"][0]["value"])
    decimals = balance["balances"][0]["currency"]["decimals"]
    symbol = balance["balances"][0]["currency"]["symbol"]
    return f"{value / 10**decimals} {symbol} ({value} raw)"

def string_to_bytes(text):
    """Convert string to a list of byte values for memo"""
    if not text:
        return None
        
    # Use ASCII encoding
    return [ord(c) for c in text]

def main():
    parser = argparse.ArgumentParser(description='Transfer ICRC-1 tokens using Rosetta API')
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--canister-id", type=str, required=True, help="Canister ID of the ICRC-1 ledger")
    parser.add_argument("--private-key-path", type=str, required=True, help="Path to private key file")
    parser.add_argument("--signature-type", type=str, default="ecdsa", help="Signature type")
    parser.add_argument("--from-principal", type=str, required=True, help="Sender's principal identifier")
    parser.add_argument("--from-subaccount", type=str, help="Sender's subaccount in hex")
    parser.add_argument("--to-principal", type=str, required=True, help="Recipient's principal identifier")
    parser.add_argument("--to-subaccount", type=str, help="Recipient's subaccount in hex")
    parser.add_argument("--amount", type=int, required=True, help="Amount to transfer")
    parser.add_argument("--fee", type=int, required=True, help="Fee to pay")
    parser.add_argument("--memo", type=str, help="Optional memo to include with the transfer")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    client = RosettaClient(
        args.node_address,
        args.canister_id,
        args.private_key_path,
        args.signature_type,
    )

    print(f"Initiating transfer of {args.amount} raw tokens...")
    print(f"From: {args.from_principal}")
    if args.from_subaccount:
        print(f"  Subaccount: {args.from_subaccount}")
    print(f"To: {args.to_principal}")
    if args.to_subaccount:
        print(f"  Subaccount: {args.to_subaccount}")
    print(f"Fee: {args.fee} raw tokens")
    
    # Check initial balances
    print("\nChecking initial balances...")
    
    try:
        sender_initial_balance = client.get_balance(args.from_principal, args.from_subaccount, verbose=args.verbose)
        print(f"Sender Initial Balance: {parse_balance(sender_initial_balance)}")
        
        recipient_initial_balance = client.get_balance(args.to_principal, args.to_subaccount, verbose=args.verbose)
        print(f"Recipient Initial Balance: {parse_balance(recipient_initial_balance)}")
    except Exception as e:
        print(f"Error fetching initial balances: {e}")
        print("Continuing with transfer anyway...")
    
    # Prepare memo if provided
    memo = None
    if args.memo:
        memo = string_to_bytes(args.memo)
        print(f"Memo: {args.memo}")
    
    # Execute the transfer
    print("\nExecuting transfer...")
    try:
        result = client.transfer(
            args.from_principal,
            args.to_principal,
            args.amount,
            args.fee,
            from_subaccount=args.from_subaccount,
            to_subaccount=args.to_subaccount,
            memo=memo,
            verbose=args.verbose
        )
        
        print("\nTransfer submitted successfully!")
        if 'transaction_identifier' in result:
            tx_hash = result['transaction_identifier'].get('hash', 'Unknown')
            print(f"Transaction hash: {tx_hash}")
    except Exception as e:
        print(f"Error during transfer: {e}")
        return
    
    # Wait for the transaction to be finalized
    print("\nWaiting for transaction to be finalized...")
    time.sleep(5)
    
    # Check final balances
    print("\nChecking final balances...")
    try:
        sender_final_balance = client.get_balance(args.from_principal, args.from_subaccount, verbose=args.verbose)
        print(f"Sender Final Balance: {parse_balance(sender_final_balance)}")
        
        recipient_final_balance = client.get_balance(args.to_principal, args.to_subaccount, verbose=args.verbose)
        print(f"Recipient Final Balance: {parse_balance(recipient_final_balance)}")
        
        # Calculate and show the difference if initial balances were retrieved
        try:
            sender_initial = int(sender_initial_balance["balances"][0]["value"])
            sender_final = int(sender_final_balance["balances"][0]["value"])
            sender_diff = sender_final - sender_initial
            
            recipient_initial = int(recipient_initial_balance["balances"][0]["value"])
            recipient_final = int(recipient_final_balance["balances"][0]["value"])
            recipient_diff = recipient_final - recipient_initial
            
            decimals = sender_initial_balance["balances"][0]["currency"]["decimals"]
            symbol = sender_initial_balance["balances"][0]["currency"]["symbol"]
            
            print(f"\nSender balance change: {sender_diff / 10**decimals} {symbol} ({sender_diff} raw)")
            print(f"Recipient balance change: {recipient_diff / 10**decimals} {symbol} ({recipient_diff} raw)")
            
            expected_sender_diff = -(args.amount + args.fee)
            if sender_diff != expected_sender_diff:
                print(f"\nWarning: Sender balance change ({sender_diff}) doesn't match expected ({expected_sender_diff})")
                print("This could be due to other transactions affecting the account during this time.")
                
            if recipient_diff != args.amount:
                print(f"\nWarning: Recipient balance change ({recipient_diff}) doesn't match transfer amount ({args.amount})")
                print("This could be due to other transactions affecting the account during this time.")
        except:
            print("\nCouldn't calculate balance differences. This could be due to errors retrieving the initial balances.")
            
    except Exception as e:
        print(f"Error fetching final balances: {e}")

if __name__ == "__main__":
    main() 