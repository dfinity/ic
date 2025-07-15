#!/usr/bin/env python3
r"""
Transfer ICP Example

This script demonstrates how to transfer ICP tokens from one account to another
using the Internet Computer Rosetta API. It shows the initial balances of both
accounts, performs the transfer, and then displays the final balances to confirm
the transaction was successful.

To use this script, you need:
1. A Rosetta node address
2. A private key file for the sender account
3. The recipient's account ID
4. The amount to transfer (in e8s, where 1 ICP = 100,000,000 e8s)
5. The fee to include (typically 10,000 e8s)

Examples:
    # Basic transfer of 0.01 ICP with standard fee
    python3 transfer.py --node-address http://localhost:8081 \\
                       --funded-private-key-pem ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --recipient-account-id 47e0ae0de8af04a961c4b3225cd77b9652777286ce142c2a07fab98da5263100 \\
                       --amount-e8s 1000000 \\
                       --fee-e8s 10000

    # With verbose output for debugging
    python3 transfer.py --node-address http://localhost:8081 \\
                       --funded-private-key-pem ./my_private_key.pem \\
                       --signature-type ecdsa \\
                       --recipient-account-id 47e0ae0de8af04a961c4b3225cd77b9652777286ce142c2a07fab98da5263100 \\
                       --amount-e8s 1000000 \\
                       --fee-e8s 10000 \\
                       --verbose

"""

import argparse
import time

from rosetta_client import RosettaClient


def parse_balance(balance):
    return int(balance["balances"][0]["value"]) / 10 ** balance["balances"][0]["currency"]["decimals"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-address", type=str)
    parser.add_argument("--funded-private-key-pem", type=str)
    parser.add_argument("--signature-type", type=str)
    parser.add_argument("--recipient-account-id", type=str)
    parser.add_argument("--amount-e8s", type=int)
    parser.add_argument("--fee-e8s", type=int)
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    client1 = RosettaClient(
        args.node_address,
        args.funded_private_key_pem,
        args.signature_type,
    )

    initial_balance = parse_balance(client1.get_balance())
    print(f"Initial Balance: {initial_balance}")

    recipient_initial_balance = parse_balance(client1.get_balance(args.recipient_account_id))
    print(f"Recipient Initial Balance: {recipient_initial_balance}")

    client1.transfer(args.recipient_account_id, args.amount_e8s, args.fee_e8s, verbose=args.verbose)

    time.sleep(3)

    final_balance = parse_balance(client1.get_balance())
    print(f"Final Balance: {final_balance}")

    recipient_final_balance = parse_balance(client1.get_balance(args.recipient_account_id))
    print(f"Recipient Final Balance: {recipient_final_balance}")


if __name__ == "__main__":
    main()
