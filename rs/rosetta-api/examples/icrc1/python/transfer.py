#!/usr/bin/env python3
r"""
Transfer ICRC-1 Tokens Example

This script demonstrates how to transfer ICRC-1 tokens from one account to another
using the Internet Computer Rosetta API. It shows the initial balances of both
accounts, performs the transfer, and then displays the final balances to confirm
the transaction was successful.

To use this script, you need:
1. A Rosetta node address
2. The canister ID of the ICRC-1 ledger
3. A private key file for the sender account
4. The recipient's principal ID and optional subaccount
5. The amount to transfer
6. The fee to include

Examples:
    # Basic transfer with standard fee
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id <canister-id> \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --to-principal <to-principal-id> \\
                       --amount <amount> \\
                       --fee <fee>

    # Transfer with subaccounts
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id <canister-id> \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --from-subaccount <from-subaccount> \\
                       --to-principal <to-principal-id> \\
                       --to-subaccount <to-subaccount> \\
                       --amount <amount> \\
                       --fee <fee>

    # With memo
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id <canister-id> \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --to-principal <to-principal-id> \\
                       --amount <amount> \\
                       --fee <fee> \\
                       --memo "Payment for services"

    # With verbose output for debugging
    python3 transfer.py --node-address http://localhost:8082 \\
                       --canister-id <canister-id> \\
                       --private-key-path ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --to-principal <to-principal-id> \\
                       --amount <amount> \\
                       --fee <fee> \\
                       --verbose

Required Parameters:
    --node-address:     URL of the Rosetta API endpoint
    --canister-id:      Canister ID of the ICRC-1 ledger
    --private-key-path: Path to the private key file
    --signature-type:   Signature type
    --from-subaccount:   Sender's subaccount in hex
    --to-principal:     Recipient's principal identifier
    --to-subaccount:    Recipient's subaccount in hex
    --amount:           Amount to transfer
    --fee:              Fee to pay

"""

import argparse
import sys
import time

from rosetta_client import RosettaClient


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
    parser = argparse.ArgumentParser(description="Transfer ICRC-1 tokens using Rosetta API")
    parser.add_argument("--node-address", type=str, required=True, help="Rosetta node address")
    parser.add_argument("--canister-id", type=str, required=True, help="Canister ID of the ICRC-1 ledger")
    parser.add_argument("--private-key-path", type=str, required=True, help="Path to private key file")
    parser.add_argument("--signature-type", type=str, required=True, help="Signature type")
    parser.add_argument("--from-subaccount", type=str, help="Sender's subaccount in hex")
    parser.add_argument("--to-principal", type=str, required=True, help="Recipient's principal identifier")
    parser.add_argument("--to-subaccount", type=str, help="Recipient's subaccount in hex")
    parser.add_argument("--amount", type=int, required=True, help="Amount to transfer")
    parser.add_argument("--fee", type=int, required=True, help="Fee to pay")
    parser.add_argument("--memo", type=str, help="Optional memo to include with the transfer")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--token-name", type=str, help="Token name (symbol) to use for the transfer (overrides API response)"
    )
    parser.add_argument(
        "--token-decimals", type=int, help="Token decimals to use for the transfer (overrides API response)"
    )

    args = parser.parse_args()

    # Initialize the Rosetta client
    client = RosettaClient(node_address=args.node_address, canister_id=args.canister_id, verbose=args.verbose)

    if args.verbose:
        print(f"Using network: {client.network['network']} (blockchain: {client.network['blockchain']})")
        print(f"Auto-discovered token: {client.token_info['symbol']} (decimals: {client.token_info['decimals']})")

        # Get network options to understand how the API should be used
        try:
            options = client.get_options(verbose=True)
            print("\nSupported operations and currencies:")
            if "allow" in options:
                if "operation_types" in options["allow"]:
                    print(f"Operation types: {', '.join(options['allow']['operation_types'])}")
                if "currencies" in options["allow"]:
                    for currency in options["allow"]["currencies"]:
                        print(f"Currency: {currency['symbol']} (decimals: {currency['decimals']})")
        except Exception as e:
            print(f"Could not fetch network options: {e}")

    # Set token override if explicitly provided by command line
    if args.token_name is not None and args.token_decimals is not None:
        client.token_override = {"symbol": args.token_name, "decimals": args.token_decimals}
        print(f"Using token override: {args.token_name} with {args.token_decimals} decimals")

    # Set up the private key
    client.setup_keys(private_key_path=args.private_key_path)

    # Derive the sender principal from the private key
    try:
        key_info = RosettaClient.derive_key_info(private_key_path=args.private_key_path, verbose=args.verbose)
        from_principal = key_info["principal_id"]
        print(f"Derived sender principal from private key: {from_principal}")
    except Exception as e:
        print(f"Error deriving principal from private key: {e}")
        print("Please check that your private key file is valid.")
        return

    # Get token info for display (uses override if set, otherwise auto-discovered info)
    token_info = client.token_override if client.token_override else client.token_info
    decimals = token_info["decimals"]
    symbol = token_info["symbol"]

    # Show human-readable amount
    human_amount = args.amount / (10**decimals)
    human_fee = args.fee / (10**decimals)

    print(f"Initiating transfer of {human_amount} {symbol} ({args.amount} raw tokens)...")
    print(f"From: {from_principal}")
    if args.from_subaccount:
        print(f"  Subaccount: {args.from_subaccount}")
    print(f"To: {args.to_principal}")
    if args.to_subaccount:
        print(f"  Subaccount: {args.to_subaccount}")
    print(f"Fee: {human_fee} {symbol} ({args.fee} raw tokens)")

    # Check initial balances
    print("\nChecking initial balances...")

    # Handle optional subaccounts with None values if not provided
    from_subaccount = args.from_subaccount if args.from_subaccount else None
    to_subaccount = args.to_subaccount if args.to_subaccount else None

    try:
        sender_initial_balance = client.get_balance(
            principal=from_principal, subaccount=from_subaccount, verbose=args.verbose
        )
        print(f"Sender Initial Balance: {parse_balance(sender_initial_balance)}")

        recipient_initial_balance = client.get_balance(
            principal=args.to_principal, subaccount=to_subaccount, verbose=args.verbose
        )
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
            from_principal=from_principal,
            to_principal=args.to_principal,
            amount=args.amount,
            fee=args.fee,
            private_key_path=args.private_key_path,
            signature_type=args.signature_type,
            from_subaccount=from_subaccount,
            to_subaccount=to_subaccount,
            memo=memo,
            verbose=args.verbose,
        )

        print("\nTransfer submitted successfully!")
        if "transaction_identifier" in result:
            tx_hash = result["transaction_identifier"].get("hash", "Unknown")
            print(f"Transaction hash: {tx_hash}")
    except Exception as e:
        print(f"Error during transfer: {e}")
        return

    # Wait for the transaction to be finalized
    print("\nWaiting for transaction to be finalized...")
    time.sleep(5)

    # Check final balances
    print("\nChecking final balances...")
    exit_with_error = False
    try:
        sender_final_balance = client.get_balance(
            principal=from_principal, subaccount=from_subaccount, verbose=args.verbose
        )
        print(f"Sender Final Balance: {parse_balance(sender_final_balance)}")

        recipient_final_balance = client.get_balance(
            principal=args.to_principal, subaccount=to_subaccount, verbose=args.verbose
        )
        print(f"Recipient Final Balance: {parse_balance(recipient_final_balance)}")

        # Calculate and show the difference if initial balances were retrieved
        try:
            sender_initial = int(sender_initial_balance["balances"][0]["value"])
            sender_final = int(sender_final_balance["balances"][0]["value"])
            sender_diff = sender_final - sender_initial

            recipient_initial = int(recipient_initial_balance["balances"][0]["value"])
            recipient_final = int(recipient_final_balance["balances"][0]["value"])
            recipient_diff = recipient_final - recipient_initial

            # Use the actual token info from the balance response
            decimals = sender_final_balance["balances"][0]["currency"]["decimals"]
            symbol = sender_final_balance["balances"][0]["currency"]["symbol"]

            print(f"\nSender balance change: {sender_diff / 10**decimals} {symbol} ({sender_diff} raw)")
            print(f"Recipient balance change: {recipient_diff / 10**decimals} {symbol} ({recipient_diff} raw)")

            expected_sender_diff = -(args.amount + args.fee)
            if sender_diff != expected_sender_diff:
                print(
                    f"\nWarning: Sender balance change ({sender_diff}) doesn't match expected ({expected_sender_diff})"
                )
                print("This could be due to other transactions affecting the account during this time.")
                exit_with_error = True

            if recipient_diff != args.amount:
                print(
                    f"\nWarning: Recipient balance change ({recipient_diff}) doesn't match transfer amount ({args.amount})"
                )
                print("This could be due to other transactions affecting the account during this time.")
                exit_with_error = True

            if exit_with_error:
                print("Error: Final balances do not match expected values.")
                sys.exit(1)
        except Exception as e:
            print(
                "\nCouldn't calculate balance differences. This could be due to errors retrieving the initial balances."
            )
            print(f"Error: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"Error fetching final balances: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
